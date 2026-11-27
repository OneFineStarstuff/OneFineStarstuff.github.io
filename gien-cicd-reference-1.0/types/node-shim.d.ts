declare module "node:http" { export function createServer(handler: (request: any, response: any) => void | Promise<void>): any; }
declare module "node:crypto" { export function randomUUID(): string; export function createHash(algorithm: string): any; }
declare module "node:fs/promises" { export const mkdir: any; export const readFile: any; export const readdir: any; export const lstat: any; export const writeFile: any; export const copyFile: any; export const rm: any; export const stat: any; }
declare module "node:path" { export const resolve: any; export const relative: any; export const join: any; export const dirname: any; export const basename: any; export const sep: string; export const isAbsolute: any; }
declare module "node:url" { export const fileURLToPath: any; }
declare module "node:os" { export const tmpdir: any; }
declare const process: { env: Record<string, string | undefined>; argv: string[]; exit(code?: number): never; stdout: { write(value: string): void }; stderr: { write(value: string): void }; cwd(): string; };
