import { describe, test, expect, vi } from 'vitest'
import { calculateDemographicParity } from '../lib/ai/fairness'
import { generateCAE } from '../lib/ai/interpretability'
import { Orchestrator } from '../lib/ai/orchestrator'
import { ModelProvider } from '../lib/ai/types'

describe('Governance Remediation - MAS FEAT and HKMA Ethics', () => {
  const mockInput = 'Analyze global systemic risk for retail banking.'
  const mockOutput = 'Systemic risk is currently low based on G-SRI index.'

  test('Demographic Parity calculation should return valid metrics', () => {
    const metrics = calculateDemographicParity(mockInput, mockOutput)
    expect(metrics.demographicParity).toBeGreaterThanOrEqual(0.8)
    expect(metrics.isFair).toBe(true)
    expect(metrics.threshold).toBe(0.8)
  })

  test('CAE generation should return attribution and context', () => {
    const cae = generateCAE(mockInput, mockOutput)
    expect(cae.attribution).toContain('MoE_Expert')
    expect(cae.confidence).toBeGreaterThan(0.9)
    expect(cae.context).toContain('MAS/HKMA')
  })

  test('Orchestrator should attach fairness and CAE metadata for depth layer', async () => {
    const mockSurface: ModelProvider = {
      id: 'surface',
      supportsStreaming: false,
      invoke: vi.fn().mockResolvedValue({ text: 'Surface response', meta: { layer: 'surface' } }),
      stream: vi.fn()
    }
    const mockDepth: ModelProvider = {
      id: 'depth',
      supportsStreaming: false,
      invoke: vi.fn().mockResolvedValue({ text: 'Depth response', meta: { layer: 'depth' } }),
      stream: vi.fn()
    }
    const orchestrator = new Orchestrator(mockSurface, mockDepth, () => 'analytical')

    const response = await orchestrator.respond(mockInput, false)

    expect(response.meta.layer).toBe('depth')
    expect(response.meta.fairness).toBeDefined()
    expect(response.meta.fairness?.isFair).toBe(true)
    expect(response.meta.cae).toBeDefined()
    expect(response.meta.cae?.confidence).toBeGreaterThan(0.9)
  })
})
