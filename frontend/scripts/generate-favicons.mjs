import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FLARE_COUNT = 18;
const SVG_SIZE = 64;
const CORE_RADIUS = 12;
const ORBIT_OFFSET = 14; // How far each sun is from center diagonally

// Seeded random for reproducible results
let seed = 42;
function seededRandom() {
  seed = (seed * 16807) % 2147483647;
  return (seed - 1) / 2147483646;
}

function getFlarePath(angle, coreRadius, currentLen, leanIntensity) {
  const baseWidth = 0.18;
  const midDist = coreRadius + (currentLen - coreRadius) * 0.5;

  const getX = (ang, r) => Math.cos(ang) * r;
  const getY = (ang, r) => Math.sin(ang) * r;

  const x1 = getX(angle - baseWidth, coreRadius);
  const y1 = getY(angle - baseWidth, coreRadius);
  const x2 = getX(angle + baseWidth, coreRadius);
  const y2 = getY(angle + baseWidth, coreRadius);
  const tx = getX(angle, currentLen);
  const ty = getY(angle, currentLen);

  const cx = getX(angle, midDist) + (-Math.sin(angle) * leanIntensity);
  const cy = getY(angle, midDist) + (Math.cos(angle) * leanIntensity);

  return `M ${x1.toFixed(2)},${y1.toFixed(2)} Q ${cx.toFixed(2)},${cy.toFixed(2)} ${tx.toFixed(2)},${ty.toFixed(2)} Q ${cx.toFixed(2)},${cy.toFixed(2)} ${x2.toFixed(2)},${y2.toFixed(2)} Z`;
}

function generateSpiralPath(scale) {
  let d = '';
  for (let i = 0; i < 30; i++) {
    const angle = 0.3 * i;
    const r = (1 + angle) * 0.7 * scale;
    const x = Math.cos(angle) * r;
    const y = Math.sin(angle) * r;
    d += `${i === 0 ? 'M' : 'L'} ${x.toFixed(2)},${y.toFixed(2)} `;
  }
  return d;
}

function generateSunGroup(centerX, centerY, isDark, rotationDeg) {
  const primaryColor = isDark ? '#ffffff' : '#0a0a0a';
  const backFlareColor = isDark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.06)';
  const frontFlareColor = isDark ? 'rgba(255,255,255,0.5)' : 'rgba(0,0,0,0.35)';
  const spiralStroke = isDark ? '#000000' : '#ffffff';

  let group = `<g transform="translate(${centerX}, ${centerY}) rotate(${rotationDeg})">`;

  // Back flares
  for (let i = 0; i < FLARE_COUNT; i++) {
    const angle = (i * Math.PI * 2) / FLARE_COUNT;
    const lenMult = 1.0 + seededRandom() * 0.8;
    const currentLen = CORE_RADIUS + (8 * lenMult);
    const leanIntensity = (3 + seededRandom() * 4);
    group += `<path d="${getFlarePath(angle, CORE_RADIUS, currentLen, leanIntensity)}" fill="${backFlareColor}" />`;
  }

  // Core circle
  group += `<circle cx="0" cy="0" r="${CORE_RADIUS}" fill="${primaryColor}" />`;

  // Spiral inside
  group += `<path d="${generateSpiralPath(1)}" fill="none" stroke="${spiralStroke}" stroke-width="0.6" stroke-linecap="round" />`;

  // Front flares (opposite lean direction)
  for (let i = 0; i < FLARE_COUNT; i++) {
    const angle = (i * Math.PI * 2) / FLARE_COUNT;
    const lenMult = 1.0 + seededRandom() * 0.8;
    const currentLen = CORE_RADIUS + (8 * lenMult);
    const leanIntensity = -(3 + seededRandom() * 4);
    group += `<path d="${getFlarePath(angle, CORE_RADIUS, currentLen, leanIntensity)}" fill="${frontFlareColor}" />`;
  }

  group += `</g>`;
  return group;
}

function generateFavicon(isDark) {
  const cx = SVG_SIZE / 2;
  const cy = SVG_SIZE / 2;

  // Diagonal placement: top-left and bottom-right
  const x1 = cx - ORBIT_OFFSET;
  const y1 = cy - ORBIT_OFFSET;
  const x2 = cx + ORBIT_OFFSET;
  const y2 = cy + ORBIT_OFFSET;

  // Reset seed for each version so flares are consistent
  seed = 42;

  let svg = `<svg width="${SVG_SIZE}" height="${SVG_SIZE}" viewBox="0 0 ${SVG_SIZE} ${SVG_SIZE}" xmlns="http://www.w3.org/2000/svg">`;

  // Sun 1 at top-left diagonal
  svg += generateSunGroup(x1, y1, isDark, 15);

  // Reset seed offset for second sun
  seed = 137;

  // Sun 2 at bottom-right diagonal
  svg += generateSunGroup(x2, y2, isDark, -10);

  svg += `</svg>`;
  return svg;
}

const publicDir = path.resolve(__dirname, '..', 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

const darkSvg = generateFavicon(true);
const lightSvg = generateFavicon(false);

fs.writeFileSync(path.join(publicDir, 'favicon-dark.svg'), darkSvg);
fs.writeFileSync(path.join(publicDir, 'favicon-light.svg'), lightSvg);

console.log('✓ Generated favicon-dark.svg and favicon-light.svg in public/');
