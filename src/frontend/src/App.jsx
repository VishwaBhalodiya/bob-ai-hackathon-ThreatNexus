import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import AlertDetails from './pages/AlertDetails.jsx'
import CommanderBrief from './pages/CommanderBrief.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/alerts/:id" element={<AlertDetails />} />
        <Route path="/brief" element={<CommanderBrief />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
