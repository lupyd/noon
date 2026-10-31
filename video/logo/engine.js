// The animated Noon logo: noon-logo.svg (traced from assets/noon.webp)
// rasterised once into textures, brought to life by a shader. Flames are
// displaced by polar noise that flows outward from the sun rims (bases stay
// planted), each spiral rotates inside its unbroken orange ring, stars sit on
// top unwarped. With amp = 0 and angle = 0 the output is the static traced frame.
//
// Shared by logo/index.html (standalone preview) and the video stage.
//
//   const logo = await createLogo(canvas, { svgUrl })
//   logo.draw({ t, amp, angle, rect: [x, y, size] })   // rect: the 1024 logo square on the canvas

export const LOGO = 1024
// Flames + suns occupy x 168-874, y 194-861 of the 1024 square.
export const CONTENT_C = [521, 527]
export const CONTENT_H = 667
export const NAVY = '#232156'

const vs = `attribute vec2 p; void main() { gl_Position = vec4(p, 0., 1.); }`
const fs = `
precision highp float;
uniform sampler2D uTex, uStars, uDetail;
uniform vec4 uDetailBox;     // detail raster region: x, y, w, h (logo px)
uniform vec2 uRes;
uniform vec3 uRect;          // logo square: x, y (top-left, px), size (px)
uniform float uT, uAmp, uStarsOn;
uniform vec4 uBg;            // sky behind the logo, premultiplied (alpha 0 = transparent)
uniform vec2 uAngle;         // spiral rotation per sun, radians
uniform vec4 uSun[2];        // spin centre xy, spin radius, rim radius (logo px)
uniform vec2 uRimC[2];       // rim centre (logo px)

// Ashima 3D simplex noise (MIT)
vec3 mod289(vec3 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec4 mod289(vec4 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec4 permute(vec4 x) { return mod289(((x * 34.0) + 1.0) * x); }
vec4 taylorInvSqrt(vec4 r) { return 1.79284291400159 - 0.85373472095314 * r; }
float snoise(vec3 v) {
  const vec2 C = vec2(1.0 / 6.0, 1.0 / 3.0);
  const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
  vec3 i = floor(v + dot(v, C.yyy));
  vec3 x0 = v - i + dot(i, C.xxx);
  vec3 g = step(x0.yzx, x0.xyz);
  vec3 l = 1.0 - g;
  vec3 i1 = min(g.xyz, l.zxy);
  vec3 i2 = max(g.xyz, l.zxy);
  vec3 x1 = x0 - i1 + C.xxx;
  vec3 x2 = x0 - i2 + C.yyy;
  vec3 x3 = x0 - D.yyy;
  i = mod289(i);
  vec4 p = permute(permute(permute(i.z + vec4(0.0, i1.z, i2.z, 1.0)) + i.y + vec4(0.0, i1.y, i2.y, 1.0)) + i.x + vec4(0.0, i1.x, i2.x, 1.0));
  float n_ = 0.142857142857;
  vec3 ns = n_ * D.wyz - D.xzx;
  vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
  vec4 x_ = floor(j * ns.z);
  vec4 y_ = floor(j - 7.0 * x_);
  vec4 x = x_ * ns.x + ns.yyyy;
  vec4 y = y_ * ns.x + ns.yyyy;
  vec4 h = 1.0 - abs(x) - abs(y);
  vec4 b0 = vec4(x.xy, y.xy);
  vec4 b1 = vec4(x.zw, y.zw);
  vec4 s0 = floor(b0) * 2.0 + 1.0;
  vec4 s1 = floor(b1) * 2.0 + 1.0;
  vec4 sh = -step(h, vec4(0.0));
  vec4 a0 = b0.xzyw + s0.xzyw * sh.xxyy;
  vec4 a1 = b1.xzyw + s1.xzyw * sh.zzww;
  vec3 p0 = vec3(a0.xy, h.x);
  vec3 p1 = vec3(a0.zw, h.y);
  vec3 p2 = vec3(a1.xy, h.z);
  vec3 p3 = vec3(a1.zw, h.w);
  vec4 norm = taylorInvSqrt(vec4(dot(p0, p0), dot(p1, p1), dot(p2, p2), dot(p3, p3)));
  p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
  vec4 m = max(0.6 - vec4(dot(x0, x0), dot(x1, x1), dot(x2, x2), dot(x3, x3)), 0.0);
  m = m * m;
  return 42.0 * dot(m * m, vec4(dot(p0, x0), dot(p1, x1), dot(p2, x2), dot(p3, x3)));
}

// The opening shot is magnified ~6x on one sun; a small high-resolution raster
// of that region serves it, the full raster everything else.
vec4 tex(vec2 p) {
  vec2 d = (p - uDetailBox.xy) / uDetailBox.zw;
  if (d.x > 0.0 && d.y > 0.0 && d.x < 1.0 && d.y < 1.0) return texture2D(uDetail, d);
  return texture2D(uTex, p / 1024.0);
}

vec2 rot(vec2 v, float a) { float c = cos(a), s = sin(a); return vec2(c * v.x - s * v.y, s * v.x + c * v.y); }

// Flame displacement around one sun: tongues sway sideways and lick outward,
// with the noise field drifting away from the rim so motion reads as rising.
vec2 flame(vec2 p, vec2 c, float rim, float seed, out float rho) {
  vec2 v = p - c;
  float d = length(v);
  vec2 dir = v / max(d, 1e-3);
  vec2 tan = vec2(-dir.y, dir.x);
  rho = d - rim;
  float f = rho * 0.011 - uT * 0.8;
  vec3 q = vec3(dir * 2.4 + seed, f);
  float sway = snoise(q) + 0.15 * snoise(vec3(dir * 4.0 - seed, rho * 0.024 - uT * 1.4));
  float lick = snoise(q + vec3(11.7, 4.3, 2.9));
  // Bases stay planted on the red ring; tips move the most.
  float reach = smoothstep(6.0, 48.0, rho) * (0.55 + 0.45 * smoothstep(40.0, 140.0, rho));
  return (tan * sway * 13.0 + dir * lick * 6.0) * reach;
}

void main() {
  vec2 frag = vec2(gl_FragCoord.x, uRes.y - gl_FragCoord.y);
  vec2 p = (frag - uRect.xy) / uRect.z * 1024.0;

  // Stars sit on top, unwarped, each twinkling on its own phase.
  vec4 st = texture2D(uStars, p / 1024.0);
  float tw = 1.0 - 0.45 * uAmp * (0.5 + 0.5 * snoise(vec3(floor(p / 24.0) * 1.7, uT * 0.9)));
  st.a *= tw;

  for (int k = 0; k < 2; k++) {
    vec2 c = uSun[k].xy;
    if (length(p - c) < uSun[k].z) {
      float a = k == 0 ? uAngle.x : uAngle.y;
      gl_FragColor = tex(c + rot(p - c, -a)); // the spiral disk is opaque
      return;
    }
  }

  float r0, r1;
  vec2 d0 = flame(p, uRimC[0], uSun[0].w, 0.0, r0);
  vec2 d1 = flame(p, uRimC[1], uSun[1].w, 37.0, r1);
  // Blend the two suns' fields by proximity so there is no crease between them.
  float w0 = exp(-max(r0, 0.0) / 28.0), w1 = exp(-max(r1, 0.0) / 28.0);
  vec2 d = (d0 * w0 + d1 * w1) / max(w0 + w1, 1e-4);
  d *= smoothstep(6.0, 30.0, min(r0, r1));
  vec2 q = p - d * uAmp;
  // logo rasters are premultiplied and transparent outside the drawing
  vec4 col = (q.x < 0.0 || q.y < 0.0 || q.x > 1024.0 || q.y > 1024.0) ? vec4(0.0) : tex(q);
  vec4 base = col + uBg * (1.0 - col.a);
  float sa = st.a * uStarsOn;
  vec3 srgb = st.rgb / max(st.a, 1e-4);
  gl_FragColor = vec4(base.rgb * (1.0 - sa) + srgb * sa, base.a * (1.0 - sa) + sa);
}`


export async function createLogo(canvas, { svgUrl, tex = 4096, starTex = 4096, detail = 2048 }) {
  const svgText = await (await fetch(svgUrl)).text()
  const doc = new DOMParser().parseFromString(svgText, 'image/svg+xml')
  const suns = ['a', 'b'].map((id) => {
    const g = doc.getElementById(`sun-${id}`)
    return { c: [+g.dataset.cx, +g.dataset.cy], r: +g.dataset.r, rim: +g.dataset.rim }
  })
  // Inside each spin circle the sun content equals the flame stack beneath it, so
  // one texture of the stack serves both; the sun groups are not rasterised.
  for (const id of ['a', 'b']) doc.getElementById(`sun-${id}`).remove()

  // Two rasters: the scene without stars (it gets warped) and the stars alone on
  // transparent (drawn on top, unwarped, so they never smear with the flames).
  async function raster(size, edit, viewBox) {
    const d = doc.cloneNode(true)
    d.documentElement.setAttribute('width', size)
    d.documentElement.setAttribute('height', size)
    if (viewBox) d.documentElement.setAttribute('viewBox', viewBox.join(' '))
    edit(d)
    const img = new Image()
    img.src = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(d)], { type: 'image/svg+xml' }))
    await img.decode()
    const c = document.createElement('canvas')
    c.width = c.height = size
    c.getContext('2d').drawImage(img, 0, 0, size, size)
    return c
  }
  // The logo itself, without its night sky or stars: draw() lays the sky (or nothing) behind it.
  const bare = (d) => ['stars', 'bg'].forEach((id) => d.getElementById(id).remove())
  const sceneTex = await raster(tex, bare)
  // detail region: a square around the first sun's spiral, slightly past its rim
  const half = Math.ceil(suns[0].rim + 40)
  const box = [suns[0].c[0] - half, suns[0].c[1] - half, 2 * half, 2 * half]
  const detailTex = await raster(detail, bare, box)
  const starsTex = await raster(starTex, (d) => {
    for (const el of [...d.documentElement.children]) if (el.id !== 'stars') el.remove()
  })

  const gl = canvas.getContext('webgl', { preserveDrawingBuffer: true, antialias: false })
  function shader(type, src) {
    const s = gl.createShader(type)
    gl.shaderSource(s, src)
    gl.compileShader(s)
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s))
    return s
  }
  const prog = gl.createProgram()
  gl.attachShader(prog, shader(gl.VERTEX_SHADER, vs))
  gl.attachShader(prog, shader(gl.FRAGMENT_SHADER, fs))
  gl.linkProgram(prog)
  gl.useProgram(prog)
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer())
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW)
  gl.enableVertexAttribArray(0)
  gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)

  function upload(unit, src) {
    gl.activeTexture(gl.TEXTURE0 + unit)
    gl.bindTexture(gl.TEXTURE_2D, gl.createTexture())
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, src)
    gl.generateMipmap(gl.TEXTURE_2D)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
  }
  // The logo layers are premultiplied (clean edges when filtered over any sky);
  // the star layer stays straight alpha.
  gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, true)
  upload(0, sceneTex)
  upload(2, detailTex)
  gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false)
  upload(1, starsTex)
  // the 2D rasters are on the GPU now; drop the CPU copies
  for (const c of [sceneTex, starsTex, detailTex]) c.width = c.height = 0
  // out of GPU memory shows up here, not as an exception: fail loudly, never render black
  const err = gl.getError()
  if (err !== gl.NO_ERROR || gl.isContextLost()) throw new Error(`logo textures failed (GL error ${err})`)

  const U = (n) => gl.getUniformLocation(prog, n)
  gl.uniform1i(U('uTex'), 0)
  gl.uniform1i(U('uStars'), 1)
  gl.uniform1i(U('uDetail'), 2)
  gl.uniform4f(U('uDetailBox'), ...box)
  gl.uniform4fv(U('uSun'), suns.flatMap((s) => [s.c[0], s.c[1], s.r, s.rim]))
  // Rim radii were fitted around their own centres; the spin centre is within a
  // few px of it, close enough to share for the flame field.
  gl.uniform2fv(U('uRimC'), suns.flatMap((s) => s.c))

  return {
    suns,
    /**
     * t: animation clock (s); amp: flame strength 0..1; angle: spiral rotation (rad);
     * rect: logo square [x, y, size] in canvas px; sky: the night sky behind the logo
     * (false = transparent canvas, stars off)
     */
    draw({ t, amp, angle, rect, sky = true }) {
      const [r, g, b] = [0x23, 0x21, 0x56].map((v) => v / 255) // NAVY, the logo's own background
      gl.uniform4f(U('uBg'), ...(sky ? [r, g, b, 1] : [0, 0, 0, 0]))
      gl.uniform1f(U('uStarsOn'), sky ? 1 : 0)
      gl.clearColor(0, 0, 0, 0)
      gl.clear(gl.COLOR_BUFFER_BIT)
      gl.uniform2f(U('uRes'), canvas.width, canvas.height)
      gl.uniform1f(U('uT'), t)
      gl.uniform1f(U('uAmp'), amp)
      gl.uniform2f(U('uAngle'), angle, angle)
      gl.uniform3f(U('uRect'), ...rect)
      gl.viewport(0, 0, canvas.width, canvas.height)
      gl.drawArrays(gl.TRIANGLES, 0, 3)
    },
  }
}
