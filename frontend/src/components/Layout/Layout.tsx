import React from 'react'

interface Props {
  children: React.ReactNode
}

const Layout: React.FC<Props> = ({ children }) => {
  return (
    <div className="layout-shell">
      <header className="layout-header">
        <h1 className="layout-title">The Turning Wheel</h1>
      </header>
      <main className="layout-content">
        {children}
      </main>
    </div>
  )
}

export default Layout
