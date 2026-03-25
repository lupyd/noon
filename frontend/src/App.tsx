import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [health, setHealth] = useState<string>('Unknown')
  const [loading, setLoading] = useState<boolean>(false)

  const checkHealth = async () => {
    setLoading(true)
    try {
      const response = await fetch('http://localhost:39210/health')
      const text = await response.text()
      setHealth(text)
    } catch (error) {
      console.error('Failed to fetch health:', error)
      setHealth('Error: ' + (error as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    checkHealth()
  }, [])

  return (
    <div className="App">
      <h1>Noon Integration Test</h1>
      <div className="card">
        <p>Backend Health: <strong>{health}</strong></p>
        <button onClick={checkHealth} disabled={loading}>
          {loading ? 'Checking...' : 'Check Again'}
        </button>
      </div>
      <div className="card">
        <h2>Manual Verification Steps</h2>
        <ol style={{ textAlign: 'left', display: 'inline-block' }}>
          <li>Backend is running on port 39210</li>
          <li>Frontend is running on port 5173</li>
          <li>CORS is enabled on backend</li>
          <li>Integration tests moved to <code>tests/</code> directory</li>
        </ol>
      </div>
    </div>
  )
}

export default App
