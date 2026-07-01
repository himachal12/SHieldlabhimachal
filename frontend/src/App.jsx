import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import ScanPage from './pages/ScanPage'
import Results from './pages/Results'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/scan/:scanId" element={<ScanPage />} />
        <Route path="/results/:scanId" element={<Results />} />
      </Routes>
    </BrowserRouter>
  )
}