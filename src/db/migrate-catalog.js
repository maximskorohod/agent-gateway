// Миграция ключей при смене каталога (П-24, решение №10): ключ bitrix24, чей хост не подходит под
// облачный шаблон, становится bitrix24-box. Секрет в сейфе не трогается, пишется audit `catalog.migrated`.

/**
 * Запускается при старте после загрузки каталога; повторный запуск ничего не меняет.
 * @param {{listCredentialsByProvider: Function, migrateCredentialProvider: Function}} repo
 * @param {{get: (slug:string) => object|undefined}} catalog
 * @returns {string[]} id перенесённых ключей
 */
export function migrateCatalog(repo, catalog) {
  const cloud = catalog.get('bitrix24');
  if (!cloud?.hostPattern || !catalog.get('bitrix24-box')) return [];
  const re = new RegExp(cloud.hostPattern);
  const moved = [];
  for (const c of repo.listCredentialsByProvider('bitrix24')) {
    if (re.test(c.host)) continue;
    if (repo.migrateCredentialProvider(c.id, 'bitrix24', 'bitrix24-box')) moved.push(c.id);
  }
  return moved;
}
