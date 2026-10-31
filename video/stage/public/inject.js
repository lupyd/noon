/* Loaded first in every demo page served by scripts/serve.mjs. Inert unless the
 * page is an iframe created by the stage (window.name carries a JSON config). */
(function () {
  var cfg
  try { cfg = JSON.parse(window.name || '{}') } catch (e) { cfg = {} }
  if (!cfg || !cfg.lupydStage) return
  var theme = cfg.theme === 'light' ? 'light' : 'dark'

  // Pin the clock: every frame (and every parallel render worker) sees the same
  // "now", so relative timestamps never differ between workers. Time still
  // advances from the base so app logic that waits on Date keeps working.
  var RealDate = Date
  var base = cfg.now ? new RealDate(cfg.now).getTime() : new RealDate(2026, 9, 28, 23, 40, 5).getTime()
  var t0 = performance.now()
  var nowFn = function () { return Math.floor(base + (performance.now() - t0)) }
  function FixedDate(a, b, c, d, e, f, g) {
    if (!(this instanceof FixedDate)) return new RealDate(nowFn()).toString()
    var n = arguments.length
    return n === 0 ? new RealDate(nowFn()) : n === 1 ? new RealDate(a) : new RealDate(a, b, c === undefined ? 1 : c, d || 0, e || 0, f || 0, g || 0)
  }
  FixedDate.prototype = RealDate.prototype
  FixedDate.now = nowFn
  FixedDate.parse = RealDate.parse
  FixedDate.UTC = RealDate.UTC
  window.Date = FixedDate

  // Determinism across parallel render workers:
  // 1) seeded Math.random per page (mock data / jitter is then identical),
  var seed = 2166136261
  var key = location.pathname + location.search
  for (var i = 0; i < key.length; i++) { seed ^= key.charCodeAt(i); seed = Math.imul(seed, 16777619) >>> 0 }
  Math.random = function () {
    seed = (seed + 0x6d2b79f5) >>> 0
    var t = seed
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  // 2) fresh, private storage per page load: same-origin iframes must not see
  //    each other's persisted UI state (last channel, collapsed panes, caches),
  //    which otherwise depends on what a worker happened to load before.
  function MemStorage() { this._m = new Map() }
  MemStorage.prototype.getItem = function (k) { k = String(k); if (k === 'theme') return theme; return this._m.has(k) ? this._m.get(k) : null }
  MemStorage.prototype.setItem = function (k, v) { k = String(k); if (k === 'theme') return; this._m.set(k, String(v)) }
  MemStorage.prototype.removeItem = function (k) { this._m.delete(String(k)) }
  MemStorage.prototype.clear = function () { this._m.clear() }
  MemStorage.prototype.key = function (i) { return Array.from(this._m.keys())[i] ?? null }
  Object.defineProperty(MemStorage.prototype, 'length', { get: function () { return this._m.size } })
  try {
    Object.defineProperty(window, 'localStorage', { value: new MemStorage(), configurable: true })
    Object.defineProperty(window, 'sessionStorage', { value: new MemStorage(), configurable: true })
  } catch (e) {}
  try {
    var nonce = Math.floor(performance.timeOrigin * 1000) + '' + Math.floor(performance.now() * 1000)
    var idb = window.indexedDB
    var open = idb.open.bind(idb)
    idb.open = function (name, ver) { return ver === undefined ? open(name + '__stage' + nonce) : open(name + '__stage' + nonce, ver) }
  } catch (e) {}
  window.addEventListener('storage', function (e) { e.stopImmediatePropagation() }, true)
  // 3) IntersectionObserver judged against this page's own viewport, as if the
  //    window were fully on screen. Real IO also accounts for the parent stage
  //    (windows sliding in from off-screen, 3D tilt), so lazy avatars/media
  //    would load or not depending on when a worker happened to mount the page.
  var observers = new Set()
  function SIO(cb, opts) { this._cb = cb; this._opts = opts || {}; this._state = new Map(); observers.add(this) }
  SIO.prototype._check = function (el) {
    var r = el.getBoundingClientRect()
    var vw = window.innerWidth, vh = window.innerHeight
    var m = parseInt(String(this._opts.rootMargin || '0'), 10) || 0
    var root = this._opts.root && this._opts.root.getBoundingClientRect ? this._opts.root.getBoundingClientRect() : { left: 0, top: 0, right: vw, bottom: vh }
    var hit = r.width + r.height > 0 && r.right >= root.left - m && r.left <= root.right + m && r.bottom >= root.top - m && r.top <= root.bottom + m
    return { target: el, isIntersecting: hit, intersectionRatio: hit ? 1 : 0, boundingClientRect: r, intersectionRect: hit ? r : { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 }, rootBounds: root, time: performance.now() }
  }
  SIO.prototype._flush = function (force) {
    var out = [], self = this
    this._state.forEach(function (prev, el) {
      var e = self._check(el)
      if (force || prev === undefined || prev !== e.isIntersecting) { out.push(e); self._state.set(el, e.isIntersecting) }
    })
    if (out.length) { try { this._cb(out, this) } catch (err) { console.error(err) } }
  }
  SIO.prototype.observe = function (el) {
    var self = this
    this._state.set(el, undefined)
    Promise.resolve().then(function () { if (self._state.has(el) && self._state.get(el) === undefined) self._flush(false) })
  }
  SIO.prototype.unobserve = function (el) { this._state.delete(el) }
  SIO.prototype.disconnect = function () { this._state.clear(); observers.delete(this) }
  SIO.prototype.takeRecords = function () { return [] }
  window.IntersectionObserver = SIO
  var recheck = function () { observers.forEach(function (o) { o._flush(false) }) }
  window.addEventListener('scroll', recheck, true)
  window.addEventListener('resize', recheck)
  var mm = window.matchMedia.bind(window)
  window.matchMedia = function (q) {
    var r = mm(q)
    if (/prefers-color-scheme/.test(q)) {
      var want = /dark/.test(q) ? theme === 'dark' : theme === 'light'
      var noop = function () {}
      return { matches: want, media: q, onchange: null, addListener: noop, removeListener: noop, addEventListener: noop, removeEventListener: noop, dispatchEvent: function () { return false } }
    }
    return r
  }
  document.documentElement.classList.add(theme)
  document.documentElement.style.colorScheme = theme

  var css = [
    '*,*::before,*::after{transition:none!important;animation-duration:0s!important;animation-delay:0s!important;animation-iteration-count:1!important;caret-color:transparent!important}',
    'html,body,*{scrollbar-width:none!important}',
    '::-webkit-scrollbar{display:none!important;width:0!important;height:0!important}',
    '.z-\\[9999\\].pointer-events-none{display:none!important}',
    '*:focus,*:focus-visible{outline:none!important;box-shadow:none!important;--tw-ring-shadow:0 0 #0000!important}',
    '[data-radix-toast-viewport],[role="region"][aria-label*="otification"]{display:none!important}',
    (cfg.css || ''),
  ].join('\n')
  var style = document.createElement('style')
  style.id = '__stage_css'
  style.textContent = css
  document.head.appendChild(style)

  // keep the forced theme class even if the app toggles it
  var fix = function () {
    var h = document.documentElement
    if (!h.classList.contains(theme)) h.classList.add(theme)
    var other = theme === 'dark' ? 'light' : 'dark'
    if (h.classList.contains(other)) h.classList.remove(other)
    if (document.body) {
      if (document.body.classList.contains(other)) document.body.classList.remove(other)
      if (!document.body.classList.contains(theme)) document.body.classList.add(theme)
    }
  }
  new MutationObserver(fix).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  document.addEventListener('DOMContentLoaded', function () {
    fix()
    new MutationObserver(fix).observe(document.body, { attributes: true, attributeFilter: ['class'] })
  })
  // Deterministic freeze: once the stage has let the app settle, it calls
  // __stageFreeze() and no app timer / animation-frame callback runs again, so
  // wall-clock driven UI (call timers, typing dots, auto-replies) stops changing.
  // The stage then drives anything time-based (video currentTime, timers) itself.
  var frozen = false
  var _st = window.setTimeout, _si = window.setInterval, _raf = window.requestAnimationFrame
  window.setTimeout = function (fn, ms) {
    var a = [].slice.call(arguments, 2)
    return _st(function () { if (!frozen && typeof fn === 'function') fn.apply(null, a) }, ms)
  }
  window.setInterval = function (fn, ms) {
    var a = [].slice.call(arguments, 2)
    return _si(function () { if (!frozen && typeof fn === 'function') fn.apply(null, a) }, ms)
  }
  window.requestAnimationFrame = function (cb) { return _raf(function (ts) { if (!frozen) cb(ts) }) }
  window.__stageFreeze = function () {
    frozen = true
    document.querySelectorAll('video,audio').forEach(function (m) { try { m.pause(); m.muted = true } catch (e) {} })
  }
  // Scripted steps (real clicks into the app) run while thawed, then refreeze.
  window.__stageThaw = function () { frozen = false }
  // Helpers for scripted steps: find visible elements, press them with a full
  // pointer/mouse sequence (Radix ignores bare .click()), set React inputs.
  var vis = function (e) { var r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 }
  window.__find = function (sel, src) {
    var re = src ? new RegExp(src) : null
    return Array.prototype.slice.call(document.querySelectorAll(sel)).filter(vis).find(function (x) { return !re || re.test((x.textContent || '').trim()) }) || null
  }
  window.__press = function (e) {
    var r = e.getBoundingClientRect()
    var o = { bubbles: true, cancelable: true, composed: true, clientX: r.x + r.width / 2, clientY: r.y + r.height / 2, button: 0, buttons: 1, pointerId: 1, pointerType: 'mouse', isPrimary: true, view: window }
    var up = Object.assign({}, o, { buttons: 0 })
    e.dispatchEvent(new PointerEvent('pointerdown', o)); e.dispatchEvent(new MouseEvent('mousedown', o))
    try { e.focus() } catch (err) {}
    e.dispatchEvent(new PointerEvent('pointerup', up)); e.dispatchEvent(new MouseEvent('mouseup', up)); e.dispatchEvent(new MouseEvent('click', up))
  }
  window.__setValue = function (input, v) {
    var proto = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(input, v)
    input.dispatchEvent(new Event('input', { bubbles: true }))
  }
  window.__navigate = function (p) { history.pushState({}, '', p); window.dispatchEvent(new PopStateEvent('popstate')) }
  window.__stageFrame = cfg
})()
