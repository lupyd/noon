import { useState } from 'react';
import { Play } from 'lucide-react';

// Click-to-load YouTube embed: shows a locally hosted poster and only contacts
// YouTube (via youtube-nocookie.com) once the visitor presses play.
const VIDEO_ID = 'Nu-4eB7hwqw';
const TITLE = 'Introducing Noon - Truly Anonymous Forms | By Lupyd';

export function DemoVideo() {
  const [playing, setPlaying] = useState(false);
  const watchUrl = `https://www.youtube.com/watch?v=${VIDEO_ID}`;

  return (
    <div className="demo-video-frame">
      {playing ? (
        <iframe
          src={`https://www.youtube-nocookie.com/embed/${VIDEO_ID}?autoplay=1&rel=0&modestbranding=1&playsinline=1`}
          title={TITLE}
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
          referrerPolicy="strict-origin-when-cross-origin"
          allowFullScreen
        />
      ) : (
        <a
          href={watchUrl}
          className="demo-video-play"
          aria-label={`Play video: ${TITLE}`}
          onClick={(e) => {
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
            e.preventDefault();
            setPlaying(true);
          }}
        >
          <img
            src="/noon-demo-poster.webp"
            srcSet="/noon-demo-poster-640.webp 640w, /noon-demo-poster.webp 1280w"
            sizes="(max-width: 800px) 100vw, 800px"
            alt=""
            width={1280}
            height={720}
            loading="lazy"
            decoding="async"
          />
          <span className="demo-video-button">
            <Play size={28} fill="currentColor" />
          </span>
          <span className="demo-video-note">Plays from YouTube</span>
        </a>
      )}
    </div>
  );
}
