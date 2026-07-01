import { cvssColor } from '../utils/severity'

export default function CvssScore({ score }) {
  if (!score && score !== 0) return <span className="text-slate-500">N/A</span>

  const color = cvssColor(score)
  return (
    <span className="font-bold text-lg" style={{ color }}>
      {score.toFixed(1)}
    </span>
  )
}