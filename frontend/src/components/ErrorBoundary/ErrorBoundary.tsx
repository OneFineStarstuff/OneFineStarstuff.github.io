import React from 'react'

interface Props {
  fallback: React.ComponentType<{ error: Error }>
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('ErrorBoundary caught error', error, info)
  }

  render() {
    const { fallback: Fallback, children } = this.props
    if (this.state.hasError && this.state.error) {
      return <Fallback error={this.state.error} />
    }
    return children
  }
}

export default ErrorBoundary
