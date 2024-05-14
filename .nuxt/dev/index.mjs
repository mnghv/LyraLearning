globalThis._importMeta_={url:import.meta.url,env:process.env};import 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/node-fetch-native/dist/polyfill.mjs';
import { Server } from 'http';
import { tmpdir } from 'os';
import { join } from 'path';
import { mkdirSync } from 'fs';
import { parentPort, threadId } from 'worker_threads';
import { provider, isWindows } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/std-env/dist/index.mjs';
import { defineEventHandler, handleCacheHeaders, createEvent, useCookies, setCookie, createApp, createRouter, lazyEventHandler, deleteCookie, sendRedirect, useQuery, eventHandler } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/h3/dist/index.mjs';
import { createFetch as createFetch$1, Headers } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/ohmyfetch/dist/node.mjs';
import destr from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/destr/dist/index.mjs';
import { createRouter as createRouter$1 } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/radix3/dist/index.mjs';
import { createCall, createFetch } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/unenv/runtime/fetch/index.mjs';
import { createHooks } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/hookable/dist/index.mjs';
import { hash } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/ohash/dist/index.mjs';
import { parseURL, withQuery, joinURL } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/ufo/dist/index.mjs';
import { createStorage } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/unstorage/dist/index.mjs';
import _unstorage_drivers_fs from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/unstorage/dist/drivers/fs.mjs';
import { createTRPCHandler } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/trpc-nuxt/dist/runtime/api.mjs';
import { router as router$1, TRPCError } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/@trpc/server/dist/trpc-server.cjs.js';
import { PrismaClient } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/@prisma/client/index.js';
import { Octokit } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/octokit/dist-node/index.js';
import jwt from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/jsonwebtoken/index.js';
import { DateTime } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/luxon/src/luxon.js';
import { z } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/zod/lib/index.mjs';
import NodeCache from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/node-cache/index.js';
import { createRenderer } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/vue-bundle-renderer/dist/index.mjs';
import devalue from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/@nuxt/devalue/dist/devalue.mjs';
import { renderToString } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/vue/server-renderer/index.mjs';
import { snakeCase } from 'file:///Users/m.nghv/Sites/localhost/LyraLearning/node_modules/scule/dist/index.mjs';
import htmlTemplate from '/Users/m.nghv/Sites/localhost/LyraLearning/.nuxt/views/document.template.mjs';

const _runtimeConfig = {"app":{"baseURL":"/","buildAssetsDir":"/_nuxt/","cdnURL":""},"nitro":{"routes":{},"envPrefix":"NUXT_"},"public":{"trpc":{"baseURL":"http://localhost:3000","endpoint":"/trpc"}}};
const ENV_PREFIX = "NITRO_";
const ENV_PREFIX_ALT = _runtimeConfig.nitro.envPrefix ?? process.env.NITRO_ENV_PREFIX ?? "_";
const getEnv = (key) => {
  const envKey = snakeCase(key).toUpperCase();
  return destr(process.env[ENV_PREFIX + envKey] ?? process.env[ENV_PREFIX_ALT + envKey]);
};
function isObject(input) {
  return typeof input === "object" && !Array.isArray(input);
}
function overrideConfig(obj, parentKey = "") {
  for (const key in obj) {
    const subKey = parentKey ? `${parentKey}_${key}` : key;
    const envValue = getEnv(subKey);
    if (isObject(obj[key])) {
      if (isObject(envValue)) {
        obj[key] = { ...obj[key], ...envValue };
      }
      overrideConfig(obj[key], subKey);
    } else {
      obj[key] = envValue ?? obj[key];
    }
  }
}
overrideConfig(_runtimeConfig);
const config = deepFreeze(_runtimeConfig);
const useRuntimeConfig = () => config;
function deepFreeze(object) {
  const propNames = Object.getOwnPropertyNames(object);
  for (const name of propNames) {
    const value = object[name];
    if (value && typeof value === "object") {
      deepFreeze(value);
    }
  }
  return Object.freeze(object);
}

const globalTiming = globalThis.__timing__ || {
  start: () => 0,
  end: () => 0,
  metrics: []
};
function timingMiddleware(_req, res, next) {
  const start = globalTiming.start();
  const _end = res.end;
  res.end = (data, encoding, callback) => {
    const metrics = [["Generate", globalTiming.end(start)], ...globalTiming.metrics];
    const serverTiming = metrics.map((m) => `-;dur=${m[1]};desc="${encodeURIComponent(m[0])}"`).join(", ");
    if (!res.headersSent) {
      res.setHeader("Server-Timing", serverTiming);
    }
    _end.call(res, data, encoding, callback);
  };
  next();
}

const serverAssets = [{"baseName":"server","dir":"/Users/m.nghv/Sites/localhost/LyraLearning/server/assets"}];

const assets = createStorage();

for (const asset of serverAssets) {
  assets.mount(asset.baseName, _unstorage_drivers_fs({ base: asset.dir }));
}

const storage = createStorage({});

const useStorage = () => storage;

storage.mount('/assets', assets);

storage.mount('root', _unstorage_drivers_fs({"driver":"fs","base":"/Users/m.nghv/Sites/localhost/LyraLearning","ignore":["**/node_modules/**","**/.git/**"]}));
storage.mount('src', _unstorage_drivers_fs({"driver":"fs","base":"/Users/m.nghv/Sites/localhost/LyraLearning/server","ignore":["**/node_modules/**","**/.git/**"]}));
storage.mount('build', _unstorage_drivers_fs({"driver":"fs","base":"/Users/m.nghv/Sites/localhost/LyraLearning/.nuxt","ignore":["**/node_modules/**","**/.git/**"]}));
storage.mount('cache', _unstorage_drivers_fs({"driver":"fs","base":"/Users/m.nghv/Sites/localhost/LyraLearning/.nuxt/cache","ignore":["**/node_modules/**","**/.git/**"]}));

const defaultCacheOptions = {
  name: "_",
  base: "/cache",
  swr: true,
  maxAge: 1
};
function defineCachedFunction(fn, opts) {
  opts = { ...defaultCacheOptions, ...opts };
  const pending = {};
  const group = opts.group || "nitro";
  const name = opts.name || fn.name || "_";
  const integrity = hash([opts.integrity, fn, opts]);
  async function get(key, resolver) {
    const cacheKey = [opts.base, group, name, key + ".json"].filter(Boolean).join(":").replace(/:\/$/, ":index");
    const entry = await useStorage().getItem(cacheKey) || {};
    const ttl = (opts.maxAge ?? opts.maxAge ?? 0) * 1e3;
    if (ttl) {
      entry.expires = Date.now() + ttl;
    }
    const expired = entry.integrity !== integrity || ttl && Date.now() - (entry.mtime || 0) > ttl;
    const _resolve = async () => {
      if (!pending[key]) {
        entry.value = void 0;
        entry.integrity = void 0;
        entry.mtime = void 0;
        entry.expires = void 0;
        pending[key] = Promise.resolve(resolver());
      }
      entry.value = await pending[key];
      entry.mtime = Date.now();
      entry.integrity = integrity;
      delete pending[key];
      useStorage().setItem(cacheKey, entry).catch((error) => console.error("[nitro] [cache]", error));
    };
    const _resolvePromise = expired ? _resolve() : Promise.resolve();
    if (opts.swr && entry.value) {
      _resolvePromise.catch(console.error);
      return Promise.resolve(entry);
    }
    return _resolvePromise.then(() => entry);
  }
  return async (...args) => {
    const key = (opts.getKey || getKey)(...args);
    const entry = await get(key, () => fn(...args));
    let value = entry.value;
    if (opts.transform) {
      value = await opts.transform(entry, ...args) || value;
    }
    return value;
  };
}
const cachedFunction = defineCachedFunction;
function getKey(...args) {
  return args.length ? hash(args, {}) : "";
}
function defineCachedEventHandler(handler, opts = defaultCacheOptions) {
  const _opts = {
    ...opts,
    getKey: (event) => {
      return decodeURI(parseURL(event.req.originalUrl || event.req.url).pathname).replace(/\/$/, "/index");
    },
    group: opts.group || "nitro/handlers",
    integrity: [
      opts.integrity,
      handler
    ]
  };
  const _cachedHandler = cachedFunction(async (incomingEvent) => {
    const reqProxy = cloneWithProxy(incomingEvent.req, { headers: {} });
    const resHeaders = {};
    const resProxy = cloneWithProxy(incomingEvent.res, {
      statusCode: 200,
      getHeader(name) {
        return resHeaders[name];
      },
      setHeader(name, value) {
        resHeaders[name] = value;
        return this;
      },
      getHeaderNames() {
        return Object.keys(resHeaders);
      },
      hasHeader(name) {
        return name in resHeaders;
      },
      removeHeader(name) {
        delete resHeaders[name];
      },
      getHeaders() {
        return resHeaders;
      }
    });
    const event = createEvent(reqProxy, resProxy);
    event.context = incomingEvent.context;
    const body = await handler(event);
    const headers = event.res.getHeaders();
    headers.Etag = `W/"${hash(body)}"`;
    headers["Last-Modified"] = new Date().toUTCString();
    const cacheControl = [];
    if (opts.swr) {
      if (opts.maxAge) {
        cacheControl.push(`s-maxage=${opts.maxAge}`);
      }
      if (opts.staleMaxAge) {
        cacheControl.push(`stale-while-revalidate=${opts.staleMaxAge}`);
      } else {
        cacheControl.push("stale-while-revalidate");
      }
    } else if (opts.maxAge) {
      cacheControl.push(`max-age=${opts.maxAge}`);
    }
    if (cacheControl.length) {
      headers["Cache-Control"] = cacheControl.join(", ");
    }
    const cacheEntry = {
      code: event.res.statusCode,
      headers,
      body
    };
    return cacheEntry;
  }, _opts);
  return defineEventHandler(async (event) => {
    const response = await _cachedHandler(event);
    if (event.res.headersSent || event.res.writableEnded) {
      return response.body;
    }
    if (handleCacheHeaders(event, {
      modifiedTime: new Date(response.headers["Last-Modified"]),
      etag: response.headers.etag,
      maxAge: opts.maxAge
    })) {
      return;
    }
    event.res.statusCode = response.code;
    for (const name in response.headers) {
      event.res.setHeader(name, response.headers[name]);
    }
    return response.body;
  });
}
function cloneWithProxy(obj, overrides) {
  return new Proxy(obj, {
    get(target, property, receiver) {
      if (property in overrides) {
        return overrides[property];
      }
      return Reflect.get(target, property, receiver);
    },
    set(target, property, value, receiver) {
      if (property in overrides) {
        overrides[property] = value;
        return true;
      }
      return Reflect.set(target, property, value, receiver);
    }
  });
}
const cachedEventHandler = defineCachedEventHandler;

const plugins = [
  
];

function hasReqHeader(req, header, includes) {
  const value = req.headers[header];
  return value && typeof value === "string" && value.toLowerCase().includes(includes);
}
function isJsonRequest(event) {
  return hasReqHeader(event.req, "accept", "application/json") || hasReqHeader(event.req, "user-agent", "curl/") || hasReqHeader(event.req, "user-agent", "httpie/") || event.req.url?.endsWith(".json") || event.req.url?.includes("/api/");
}
function normalizeError(error) {
  const cwd = process.cwd();
  const stack = (error.stack || "").split("\n").splice(1).filter((line) => line.includes("at ")).map((line) => {
    const text = line.replace(cwd + "/", "./").replace("webpack:/", "").replace("file://", "").trim();
    return {
      text,
      internal: line.includes("node_modules") && !line.includes(".cache") || line.includes("internal") || line.includes("new Promise")
    };
  });
  const statusCode = error.statusCode || 500;
  const statusMessage = error.statusMessage ?? (statusCode === 404 ? "Route Not Found" : "Internal Server Error");
  const message = error.message || error.toString();
  return {
    stack,
    statusCode,
    statusMessage,
    message
  };
}

const errorHandler = (async function errorhandler(_error, event) {
  const { stack, statusCode, statusMessage, message } = normalizeError(_error);
  const errorObject = {
    url: event.req.url,
    statusCode,
    statusMessage,
    message,
    description: statusCode !== 404 ? `<pre>${stack.map((i) => `<span class="stack${i.internal ? " internal" : ""}">${i.text}</span>`).join("\n")}</pre>` : "",
    data: _error.data
  };
  event.res.statusCode = errorObject.statusCode;
  event.res.statusMessage = errorObject.statusMessage;
  if (errorObject.statusCode !== 404) {
    console.error("[nuxt] [request error]", errorObject.message + "\n" + stack.map((l) => "  " + l.text).join("  \n"));
  }
  if (isJsonRequest(event)) {
    event.res.setHeader("Content-Type", "application/json");
    event.res.end(JSON.stringify(errorObject));
    return;
  }
  const url = withQuery("/__nuxt_error", errorObject);
  const html = await $fetch(url).catch((error) => {
    console.error("[nitro] Error while generating error response", error);
    return errorObject.statusMessage;
  });
  event.res.setHeader("Content-Type", "text/html;charset=UTF-8");
  event.res.end(html);
});

let cache;
function getCache() {
  if (!cache) {
    cache = new NodeCache({
      stdTTL: 60 * 10
    });
  }
  return cache;
}

const ANONYMOUS_COOKIE = "kk_anonymous_token";
const GH_COOKIE = "kk_gh_token";

let prisma;
const DEFAULT_BOX = {
  name: "German"
};
const DEFAULT_CARDS = [
  {
    front: "Hallo",
    back: "Hello"
  },
  {
    front: "Liebe",
    back: "Love"
  },
  {
    front: "Haus",
    back: "House"
  },
  {
    front: "Du",
    back: "You"
  },
  {
    front: "Wir",
    back: "We"
  },
  {
    front: "Gut",
    back: "Good"
  }
];
async function getAnonymousUser(event, prisma2) {
  const token = useCookies(event)[ANONYMOUS_COOKIE];
  if (token) {
    try {
      const authUser2 = jwt.verify(token, process.env.JWT_SECRET);
      const user2 = await prisma2.user.findFirst({
        where: {
          id: authUser2.id
        }
      });
      if (user2) {
        return authUser2;
      }
    } catch (e) {
      console.log("Invalid token", e);
    }
  }
  const user = await prisma2.user.create({
    data: {
      boxes: {
        create: [
          {
            ...DEFAULT_BOX,
            cards: {
              create: DEFAULT_CARDS
            }
          }
        ]
      }
    }
  });
  const authUser = { id: user.id };
  const newToken = jwt.sign(authUser, process.env.JWT_SECRET, {
    expiresIn: "2y"
  });
  setCookie(event, ANONYMOUS_COOKIE, newToken, {
    path: "/",
    httpOnly: true,
    secure: false,
    expires: DateTime.now().plus({ years: 2 }).toJSDate()
  });
  return authUser;
}
async function getUserFromHeader(event, prisma2) {
  const ghToken = useCookies(event)[GH_COOKIE];
  if (!ghToken) {
    return getAnonymousUser(event, prisma2);
  }
  const cache = getCache();
  const cachedUser = cache.get(ghToken);
  if (cachedUser) {
    return cachedUser;
  }
  const octokit = new Octokit({ auth: ghToken });
  const { data, status } = await octokit.rest.users.getAuthenticated();
  if (status >= 400) {
    return getAnonymousUser(event, prisma2);
  }
  let user = await prisma2.user.findFirst({
    where: {
      githubId: data.id
    }
  });
  if (!user) {
    const anonymousUser = await getAnonymousUser(event, prisma2);
    user = await prisma2.user.update({
      where: {
        id: anonymousUser.id
      },
      data: {
        githubId: data.id
      }
    });
  }
  const githubUser = {
    id: user.id,
    githubId: data.id,
    avatarUrl: data.avatar_url
  };
  cache.set(ghToken, githubUser);
  return githubUser;
}
async function createContext(event) {
  if (!prisma) {
    prisma = new PrismaClient();
  }
  const authUser = await getUserFromHeader(event, prisma);
  return {
    authUser,
    prisma
  };
}

const users = router$1().query("get", {
  resolve({ ctx }) {
    return ctx.authUser;
  }
});

async function getBox(ctx, boxId, includeCards = false) {
  const user = ctx.authUser;
  const box = await ctx.prisma.box.findFirst({
    where: {
      id: boxId,
      userId: user.id
    },
    include: {
      cards: includeCards
    }
  });
  if (!box)
    throw new TRPCError({ code: "NOT_FOUND" });
  return box;
}
const boxes = router$1().query("getAll", {
  async resolve({ ctx }) {
    const user = ctx.authUser;
    const boxes2 = await ctx.prisma.box.findMany({
      where: {
        userId: user.id
      },
      include: {
        _count: {
          select: { cards: true }
        }
      }
    });
    return boxes2;
  }
}).query("get", {
  input: z.object({
    id: z.number()
  }),
  async resolve({ ctx, input }) {
    const box = await getBox(ctx, input.id, true);
    return box;
  }
}).mutation("create", {
  input: z.object({
    name: z.string().min(1),
    cards: z.array(z.object({
      front: z.string().min(1),
      back: z.string().min(1)
    }))
  }),
  async resolve({ ctx, input }) {
    const user = ctx.authUser;
    const box = await ctx.prisma.box.create({
      data: {
        name: input.name,
        userId: user.id,
        cards: {
          create: input.cards
        }
      }
    });
    return box;
  }
}).mutation("update", {
  input: z.object({
    id: z.number(),
    name: z.string().min(1),
    cards: z.array(z.object({
      id: z.number().optional(),
      front: z.string().min(1),
      back: z.string().min(1)
    }))
  }),
  async resolve({ ctx, input }) {
    const oldBox = await getBox(ctx, input.id, true);
    const existingCards = input.cards.filter(({ id }) => id != null);
    const newCards = input.cards.filter(({ id }) => id == null);
    const deletedCardIds = oldBox.cards.filter((oldCard) => !existingCards.some((card) => card.id === oldCard.id)).map((oldCard) => oldCard.id);
    const cardUpdates = existingCards.map((card) => ctx.prisma.card.update({
      where: {
        id: card.id
      },
      data: {
        front: card.front,
        back: card.back
      }
    }));
    await ctx.prisma.$transaction(cardUpdates);
    const box = await ctx.prisma.box.update({
      where: {
        id: input.id
      },
      data: {
        name: input.name,
        cards: {
          deleteMany: {
            id: { in: deletedCardIds }
          },
          create: newCards
        }
      }
    });
    return box;
  }
}).mutation("reset", {
  input: z.object({
    id: z.number()
  }),
  async resolve({ ctx, input }) {
    await getBox(ctx, input.id);
    await ctx.prisma.card.updateMany({
      where: {
        boxId: input.id
      },
      data: {
        errorCount: 0,
        successCount: 0
      }
    });
    return true;
  }
}).mutation("delete", {
  input: z.object({
    id: z.number()
  }),
  async resolve({ ctx, input }) {
    await getBox(ctx, input.id);
    await ctx.prisma.card.deleteMany({
      where: {
        boxId: input.id
      }
    });
    await ctx.prisma.box.delete({
      where: {
        id: input.id
      }
    });
    return true;
  }
});

async function checkPermission(ctx, id) {
  const user = ctx.authUser;
  const card = await ctx.prisma.card.findFirst({
    where: {
      id,
      box: {
        userId: user.id
      }
    }
  });
  if (!card)
    throw new TRPCError({ code: "NOT_FOUND" });
}
const cards = router$1().mutation("addError", {
  input: z.object({
    id: z.number()
  }),
  async resolve({ ctx, input }) {
    await checkPermission(ctx, input.id);
    await ctx.prisma.card.update({
      where: {
        id: input.id
      },
      data: {
        errorCount: {
          increment: 1
        },
        lastTryAt: new Date()
      }
    });
    return true;
  }
}).mutation("addSuccess", {
  input: z.object({
    id: z.number()
  }),
  async resolve({ ctx, input }) {
    await checkPermission(ctx, input.id);
    await ctx.prisma.card.update({
      where: {
        id: input.id
      },
      data: {
        successCount: {
          increment: 1
        },
        lastTryAt: new Date()
      }
    });
    return true;
  }
});

const router = router$1().merge("users.", users).merge("boxes.", boxes).merge("cards.", cards);

const functions = /*#__PURE__*/Object.freeze({
  __proto__: null,
  router: router,
  createContext: createContext
});

const _CYPXfQ = createTRPCHandler({
  ...functions,
  endpoint: "/trpc"
});

const _lazy_tv9jL3 = () => Promise.resolve().then(function () { return logout$1; });
const _lazy_mSy2q5 = () => Promise.resolve().then(function () { return login$1; });
const _lazy_aCvxRQ = () => Promise.resolve().then(function () { return callback$1; });
const _lazy_aB99wI = () => Promise.resolve().then(function () { return renderer$1; });

const handlers = [
  { route: '/api/auth/logout', handler: _lazy_tv9jL3, lazy: true, middleware: false, method: undefined },
  { route: '/api/auth/login', handler: _lazy_mSy2q5, lazy: true, middleware: false, method: undefined },
  { route: '/api/auth/callback', handler: _lazy_aCvxRQ, lazy: true, middleware: false, method: undefined },
  { route: '/__nuxt_error', handler: _lazy_aB99wI, lazy: true, middleware: false, method: undefined },
  { route: '/trpc/*', handler: _CYPXfQ, lazy: false, middleware: false, method: undefined },
  { route: '/**', handler: _lazy_aB99wI, lazy: true, middleware: false, method: undefined }
];

function createNitroApp() {
  const config = useRuntimeConfig();
  const hooks = createHooks();
  const h3App = createApp({
    debug: destr(true),
    onError: errorHandler
  });
  h3App.use(config.app.baseURL, timingMiddleware);
  const router = createRouter();
  const routerOptions = createRouter$1({ routes: config.nitro.routes });
  for (const h of handlers) {
    let handler = h.lazy ? lazyEventHandler(h.handler) : h.handler;
    const referenceRoute = h.route.replace(/:\w+|\*\*/g, "_");
    const routeOptions = routerOptions.lookup(referenceRoute) || {};
    if (routeOptions.swr) {
      handler = cachedEventHandler(handler, {
        group: "nitro/routes"
      });
    }
    if (h.middleware || !h.route) {
      const middlewareBase = (config.app.baseURL + (h.route || "/")).replace(/\/+/g, "/");
      h3App.use(middlewareBase, handler);
    } else {
      router.use(h.route, handler, h.method);
    }
  }
  h3App.use(config.app.baseURL, router);
  const localCall = createCall(h3App.nodeHandler);
  const localFetch = createFetch(localCall, globalThis.fetch);
  const $fetch = createFetch$1({ fetch: localFetch, Headers, defaults: { baseURL: config.app.baseURL } });
  globalThis.$fetch = $fetch;
  const app = {
    hooks,
    h3App,
    router,
    localCall,
    localFetch
  };
  for (const plugin of plugins) {
    plugin(app);
  }
  return app;
}
const nitroApp = createNitroApp();

const server = new Server(nitroApp.h3App.nodeHandler);
function getAddress() {
  if (provider === "stackblitz" || process.env.NITRO_NO_UNIX_SOCKET) {
    return "0";
  }
  const socketName = `worker-${process.pid}-${threadId}.sock`;
  if (isWindows) {
    return join("\\\\.\\pipe\\nitro", socketName);
  } else {
    const socketDir = join(tmpdir(), "nitro");
    mkdirSync(socketDir, { recursive: true });
    return join(socketDir, socketName);
  }
}
const listenAddress = getAddress();
server.listen(listenAddress, () => {
  const _address = server.address();
  parentPort.postMessage({
    event: "listen",
    address: typeof _address === "string" ? { socketPath: _address } : { host: "localhost", port: _address.port }
  });
});
{
  process.on("unhandledRejection", (err) => console.error("[nitro] [dev] [unhandledRejection]", err));
  process.on("uncaughtException", (err) => console.error("[nitro] [dev] [uncaughtException]", err));
}

const logout = defineEventHandler((event) => {
  const ghToken = useCookies(event)[GH_COOKIE];
  if (!ghToken) {
    return true;
  }
  getCache().del(ghToken);
  deleteCookie(event, GH_COOKIE);
  return true;
});

const logout$1 = /*#__PURE__*/Object.freeze({
  __proto__: null,
  'default': logout
});

const login = defineEventHandler((event) => sendRedirect(event, `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&scope=user:email`));

const login$1 = /*#__PURE__*/Object.freeze({
  __proto__: null,
  'default': login
});

const callback = defineEventHandler(async (event) => {
  const { code } = useQuery(event);
  if (!code) {
    return sendRedirect(event, "/");
  }
  const response = await $fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    body: {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code
    }
  });
  if (response.error) {
    return sendRedirect(event, "/");
  }
  setCookie(event, GH_COOKIE, response.access_token, {
    path: "/",
    httpOnly: true,
    secure: false,
    expires: DateTime.now().plus({ days: 7 }).toJSDate()
  });
  return sendRedirect(event, "/");
});

const callback$1 = /*#__PURE__*/Object.freeze({
  __proto__: null,
  'default': callback
});

function buildAssetsURL(...path) {
  return joinURL(publicAssetsURL(), useRuntimeConfig().app.buildAssetsDir, ...path);
}
function publicAssetsURL(...path) {
  const publicBase = useRuntimeConfig().app.cdnURL || useRuntimeConfig().app.baseURL;
  return path.length ? joinURL(publicBase, ...path) : publicBase;
}

const getClientManifest = () => import('/Users/m.nghv/Sites/localhost/LyraLearning/.nuxt/dist/server/client.manifest.mjs').then((r) => r.default || r).then((r) => typeof r === "function" ? r() : r);
const getServerEntry = () => import('/Users/m.nghv/Sites/localhost/LyraLearning/.nuxt/dist/server/server.mjs').then((r) => r.default || r);
const getSSRRenderer = lazyCachedFunction(async () => {
  const clientManifest = await getClientManifest();
  if (!clientManifest) {
    throw new Error("client.manifest is not available");
  }
  const createSSRApp = await getServerEntry();
  if (!createSSRApp) {
    throw new Error("Server bundle is not available");
  }
  const renderer = createRenderer(createSSRApp, {
    clientManifest,
    renderToString: renderToString$1,
    publicPath: buildAssetsURL()
  });
  async function renderToString$1(input, context) {
    const html = await renderToString(input, context);
    if (process.env.NUXT_VITE_NODE_OPTIONS) {
      renderer.rendererContext.updateManifest(await getClientManifest());
    }
    return `<div id="__nuxt">${html}</div>`;
  }
  return renderer;
});
const getSPARenderer = lazyCachedFunction(async () => {
  const clientManifest = await getClientManifest();
  const renderToString = (ssrContext) => {
    const config = useRuntimeConfig();
    ssrContext.payload = {
      serverRendered: false,
      config: {
        public: config.public,
        app: config.app
      }
    };
    let entryFiles = Object.values(clientManifest).filter((fileValue) => fileValue.isEntry);
    if ("all" in clientManifest && "initial" in clientManifest) {
      entryFiles = clientManifest.initial.map((file) => ({ file }));
    }
    return Promise.resolve({
      html: '<div id="__nuxt"></div>',
      renderResourceHints: () => "",
      renderStyles: () => entryFiles.flatMap(({ css }) => css).filter((css) => css != null).map((file) => `<link rel="stylesheet" href="${buildAssetsURL(file)}">`).join(""),
      renderScripts: () => entryFiles.map(({ file }) => {
        const isMJS = !file.endsWith(".js");
        return `<script ${isMJS ? 'type="module"' : ""} src="${buildAssetsURL(file)}"><\/script>`;
      }).join("")
    });
  };
  return { renderToString };
});
const renderer = eventHandler(async (event) => {
  const ssrError = event.req.url?.startsWith("/__nuxt_error") ? useQuery(event) : null;
  const url = ssrError?.url || event.req.url;
  const ssrContext = {
    url,
    event,
    req: event.req,
    res: event.res,
    runtimeConfig: useRuntimeConfig(),
    noSSR: !!event.req.headers["x-nuxt-no-ssr"],
    error: ssrError,
    nuxt: void 0,
    payload: void 0
  };
  const renderer = ssrContext.noSSR ? await getSPARenderer() : await getSSRRenderer();
  const rendered = await renderer.renderToString(ssrContext).catch((e) => {
    if (!ssrError) {
      throw e;
    }
  });
  if (!rendered) {
    return;
  }
  if (event.res.writableEnded) {
    return;
  }
  if (ssrContext.error && !ssrError) {
    throw ssrContext.error;
  }
  if (ssrContext.nuxt?.hooks) {
    await ssrContext.nuxt.hooks.callHook("app:rendered");
  }
  const html = await renderHTML(ssrContext.payload, rendered, ssrContext);
  event.res.setHeader("Content-Type", "text/html;charset=UTF-8");
  return html;
});
async function renderHTML(payload, rendered, ssrContext) {
  const state = `<script>window.__NUXT__=${devalue(payload)}<\/script>`;
  rendered.meta = rendered.meta || {};
  if (ssrContext.renderMeta) {
    Object.assign(rendered.meta, await ssrContext.renderMeta());
  }
  return htmlTemplate({
    HTML_ATTRS: rendered.meta.htmlAttrs || "",
    HEAD_ATTRS: rendered.meta.headAttrs || "",
    HEAD: (rendered.meta.headTags || "") + rendered.renderResourceHints() + rendered.renderStyles() + (ssrContext.styles || ""),
    BODY_ATTRS: rendered.meta.bodyAttrs || "",
    BODY_PREPEND: ssrContext.teleports?.body || "",
    APP: (rendered.meta.bodyScriptsPrepend || "") + rendered.html + state + rendered.renderScripts() + (rendered.meta.bodyScripts || "")
  });
}
function lazyCachedFunction(fn) {
  let res = null;
  return () => {
    if (res === null) {
      res = fn().catch((err) => {
        res = null;
        throw err;
      });
    }
    return res;
  };
}

const renderer$1 = /*#__PURE__*/Object.freeze({
  __proto__: null,
  'default': renderer
});
//# sourceMappingURL=index.mjs.map
