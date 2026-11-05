// Сейф: значения ключей живут здесь, в базе — только ссылки (ТЗ §3)
import { createSsmVault } from './ssm.js';
import { createFileVault } from './file.js';
import { wrapVault } from '../core/infra.js';

export function createVault(config) {
  // сбой сейфа помечается как инфраструктурный: наружу он всегда 503 (П-30)
  if (config.vault === 'ssm') return wrapVault(createSsmVault(config));
  if (config.vault === 'file') return wrapVault(createFileVault(config));
  throw new Error(`Unknown vault type: ${config.vault}`);
}
