import { useEffect, useState } from 'react'

export function useInitializeApp() {
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    let mounted = true
    const init = async () => {
      try {
        // initialization placeholder completed synchronously for now
        if (!mounted) return
        setIsLoading(false)
      } catch (e) {
        if (!mounted) return
        setError(e as Error)
        setIsLoading(false)
      }
    }
    init()
    return () => {
      mounted = false
    }
  }, [])

  return { isLoading, error }
}
