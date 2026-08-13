import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { OnboardPage } from './OnboardPage.tsx'

// No router dependency for two routes — the app itself never navigates
// between them client-side, so a plain path check at startup is simpler
// than pulling in react-router for this.
const isOnboardRoute = window.location.pathname.replace(/\/+$/, '') === '/onboard'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {isOnboardRoute ? <OnboardPage /> : <App />}
  </StrictMode>,
)
