import { create } from 'zustand'

export type ThemeMode = 'mystical' | 'light' | 'dark'

interface ThemeState {
  theme: ThemeMode
  setTheme: (theme: ThemeMode) => void
}

export const useThemeStore = create<ThemeState>((set) => ({
  theme: 'mystical',
  setTheme: (theme) => set({ theme })
}))
