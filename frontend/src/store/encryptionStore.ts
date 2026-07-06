import { create } from 'zustand'

export interface EncryptionState {
  initialized: boolean
  initializeEncryption: () => Promise<void>
}

export const useEncryptionStore = create<EncryptionState>((set) => ({
  initialized: false,
  initializeEncryption: () => {
    set({ initialized: true })
  }
}))
