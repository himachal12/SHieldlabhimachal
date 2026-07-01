import { getSeverityColors } from '../utils/severity'

export default function SeverityBadge({ severity }) {
  const colors = getSeverityColors(severity)
  return (
    <span className={`
      inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold
      ${colors.badge} text-white
    `}>
      {severity}
    </span>
  )
}