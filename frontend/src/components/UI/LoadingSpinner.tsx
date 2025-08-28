import React from 'react'

interface Props {
  size?: 'small' | 'medium' | 'large'
  variant?: 'default' | 'mystical'
}

const sizeMap: Record<NonNullable<Props['size']>, number> = {
  small: 20,
  medium: 32,
  large: 48
}

const LoadingSpinner: React.FC<Props> = ({ size = 'medium', variant = 'default' }) => {
  const px = sizeMap[size]
  const classes = `spinner ${variant === 'mystical' ? 'spinner-mystical' : ''}`
  return <span className={classes} style={{ width: px, height: px }} aria-label="loading" />
}

export default LoadingSpinner
