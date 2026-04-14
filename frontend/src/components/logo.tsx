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
    const coreRadius = 150 * scale; // Increased base core radius
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

    const BASE_HEIGHT = 400; // Reference height for scaling
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
      ctx.beginPath();
      ctx.lineWidth = 6 * scale;
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
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

      // 1. Back Layer
      ctx.save();
      ctx.translate(x, y); ctx.rotate(sunRotation); ctx.translate(-x, -y);
      flareSet.back.forEach(f => f.draw(ctx, t, x, y, 'rgba(255, 255, 255, 0.15)', scale));
      ctx.restore();

      // 2. Core
      ctx.shadowBlur = 40 * scale;
      ctx.shadowColor = 'rgba(255, 255, 255, 0.2)';
      ctx.beginPath();
      ctx.arc(x, y, coreRadius, 0, Math.PI * 2);
      ctx.fillStyle = 'white';
      ctx.fill();
      ctx.shadowBlur = 0;

      // 3. Spiral
      drawSpiral(ctx, x, y, t * 0.003, scale);

      // 4. Front Layer
      ctx.save();
      ctx.translate(x, y); ctx.rotate(-sunRotation * 1.5); ctx.translate(-x, -y);
      flareSet.front.forEach(f => f.draw(ctx, t, x, y, 'rgba(255, 255, 255, 0.6)', scale));
      ctx.restore();

      ctx.restore();
    }

    const renderStatic = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;

      // Static positions instead of orbiting
      const offset = 80 * scale;
      const x1 = centerX - offset;
      const y1 = centerY;
      const x2 = centerX + offset;
      const y2 = centerY;

      // Draw suns with time = 0 for static look
      drawSun(ctx, x1, y1, 0, sun1Flares, 0, scale);
      drawSun(ctx, x2, y2, 0, sun2Flares, 0.5, scale);
    };

    renderStatic();

    return () => {
      // No animation to cancel
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
        margin: `0 -${height * 0.3}px` // Slightly more overlap
      }}
    />
  );
};
