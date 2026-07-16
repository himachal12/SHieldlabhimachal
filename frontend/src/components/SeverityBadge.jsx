import { getSeverityColors } from '../utils/severity'

export default function SeverityBadge({ severity }) {
  const colors = getSeverityColors(severity)
  return (
    <span className={`
      cyber-badge
      ${colors.badge}
    `}>
      {severity}
    </span>
  )
}