import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const config = {
    NOON_API_URL: env.NOON_API_URL || env.VITE_NOON_API_URL || "http://localhost:39210",
    MAX_PARTICIPANTS: parseInt(env.MAX_PARTICIPANTS || env.VITE_MAX_PARTICIPANTS || "10", 10)
  };

  return {
    plugins: [
      react(),
      visualizer({
        filename: 'stats.html',
        open: true,
        gzipSize: true,
        brotliSize: true,
      }),
      {
        name: 'generate-config',
        configureServer(server) {
          server.middlewares.use((req, res, next) => {
            if (req.url === '/config.json') {
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify(config, null, 2));
            } else {
              next();
            }
          });
        },
        generateBundle() {
          this.emitFile({
            type: 'asset',
            fileName: 'config.json',
            source: JSON.stringify(config, null, 2)
          });
        }
      }
    ],
    resolve: {
      alias: {
        'react': 'preact/compat',
        'react-dom': 'preact/compat',
        'react-dom/client': 'preact/compat/client',
        'react/jsx-runtime': 'preact/jsx-runtime'
      }
    },
    server: {
      port: 8080
    }
  }
})

