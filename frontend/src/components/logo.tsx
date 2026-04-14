import React, { useEffect, useRef } from 'react';

interface FlareSet {
  back: Flare[];
  front: Flare[];
}

class Flare {
  index: number;
  direction: number;
  angle: number;
  lenMult: number;
  baseWidth: number;
  leanIntensity: number;
  speed: number;

  constructor(index: number, direction: number) {
    this.index = index;
    this.direction = direction;
    this.angle = (index * Math.PI * 2) / 18; // FLARE_COUNT = 18
    this.lenMult = 1.0 + Math.random() * 1.2;
    this.baseWidth = 0.15;
    this.leanIntensity = (60 + Math.random() * 60) * direction;
    this.speed = 0.03 + Math.random() * 0.04;
  }

  draw(ctx: CanvasRenderingContext2D, t: number, x: number, y: number, color: string, scale: number) {
    const coreRadius = 150 * scale;
    const flicker = Math.sin(t * this.speed + this.index) * 20 * scale;
    const currentLen = coreRadius + (120 * this.lenMult * scale) + flicker;

    const getX = (ang: number, r: number) => x + Math.cos(ang) * r;
    const getY = (ang: number, r: number) => y + Math.sin(ang) * r;

    const x1 = getX(this.angle - this.baseWidth, coreRadius);
    const y1 = getY(this.angle - this.baseWidth, coreRadius);
    const x2 = getX(this.angle + this.baseWidth, coreRadius);
    const y2 = getY(this.angle + this.baseWidth, coreRadius);
    const tx = getX(this.angle, currentLen);
    const ty = getY(this.angle, currentLen);

    const midDist = coreRadius + (currentLen - coreRadius) * 0.5;
    const cx = getX(this.angle, midDist) + (-Math.sin(this.angle) * this.leanIntensity * scale);
    const cy = getY(this.angle, midDist) + (Math.cos(this.angle) * this.leanIntensity * scale);

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.quadraticCurveTo(cx, cy, tx, ty);
    ctx.quadraticCurveTo(cx, cy, x2, y2);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
  }
}

export const SunLogo: React.FC<{ height?: number }> = ({ height = 100 }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let time = 0;
    let animationFrameId: number;

    const BASE_HEIGHT = 400;
    const scale = height / BASE_HEIGHT;
    const FLARE_COUNT = 18;

    const sun1Flares: FlareSet = {
      back: Array.from({ length: FLARE_COUNT }, (_, i) => new Flare(i, 1)),
      front: Array.from({ length: FLARE_COUNT }, (_, i) => new Flare(i, -1))
    };
    const sun2Flares: FlareSet = {
      back: Array.from({ length: FLARE_COUNT }, (_, i) => new Flare(i, 1)),
      front: Array.from({ length: FLARE_COUNT }, (_, i) => new Flare(i, -1))
    };

    function drawSpiral(ctx: CanvasRenderingContext2D, x: number, y: number, rotation: number, scale: number) {
      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(rotation);
      const color = getComputedStyle(document.documentElement).getPropertyValue('--primary').trim() || 'white';
      ctx.beginPath();
      ctx.lineWidth = 6 * scale;
      ctx.strokeStyle = color;
      for (let i = 0; i < 40; i++) {
        const angle = 0.3 * i;
        const r = (1 + angle) * 6 * scale;
        ctx.lineTo(Math.cos(angle) * r, Math.sin(angle) * r);
      }
      ctx.stroke();
      ctx.restore();
    }

    function drawSun(ctx: CanvasRenderingContext2D, x: number, y: number, t: number, flareSet: FlareSet, sunRotation: number, scale: number) {
      const coreRadius = 150 * scale;
      ctx.save();

      const primaryColor = getComputedStyle(document.documentElement).getPropertyValue('--primary').trim() || 'white';
      const isDark = primaryColor === 'white' || primaryColor === '#ffffff';
      
      ctx.save();
      ctx.translate(x, y); ctx.rotate(sunRotation); ctx.translate(-x, -y);
      flareSet.back.forEach(f => f.draw(ctx, t, x, y, isDark ? 'rgba(255, 255, 255, 0.15)' : 'rgba(0, 0, 0, 0.05)', scale));
      ctx.restore();

      ctx.shadowBlur = 40 * scale;
      ctx.shadowColor = primaryColor === 'white' ? 'rgba(255, 255, 255, 0.2)' : 'rgba(0, 0, 0, 0.1)';
      ctx.beginPath();
      ctx.arc(x, y, coreRadius, 0, Math.PI * 2);
      ctx.fillStyle = primaryColor;
      ctx.fill();
      ctx.shadowBlur = 0;

      drawSpiral(ctx, x, y, t * 0.0008, scale);

      ctx.save();
      ctx.translate(x, y); ctx.rotate(-sunRotation * 1.5); ctx.translate(-x, -y);
      flareSet.front.forEach(f => f.draw(ctx, t, x, y, isDark ? 'rgba(255, 255, 255, 0.6)' : 'rgba(0, 0, 0, 0.4)', scale));
      ctx.restore();

      ctx.restore();
    }

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      time += 1.0;

      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;

      // Orbit logic
      const orbitRadius = 80 * scale;
      const orbitSpeed = 0.002;
      const x1 = centerX + Math.cos(time * orbitSpeed) * orbitRadius;
      const y1 = centerY + Math.sin(time * orbitSpeed) * orbitRadius;
      const x2 = centerX + Math.cos(time * orbitSpeed + Math.PI) * orbitRadius;
      const y2 = centerY + Math.sin(time * orbitSpeed + Math.PI) * orbitRadius;

      drawSun(ctx, x1, y1, time, sun1Flares, time * 0.002, scale);
      drawSun(ctx, x2, y2, time, sun2Flares, 0.5 + time * 0.003, scale);

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [height]);

  return (
    <canvas
      ref={canvasRef}
      width={height * 3.5}
      height={height * 2.5}
      style={{
        height: height * 1.2,
        width: height * 1.8,
        verticalAlign: 'middle',
        margin: `0 -${height * 0.3}px`
      }}
    />
  );
};
