import { Moon, Sun } from 'lucide-react';

interface Props { dark: boolean; onToggle: () => void; }

export default function ThemeToggle({ dark, onToggle }: Props) {
  return (
    <button
      onClick={onToggle}
      aria-label="Toggle color theme"
      className="p-2 rounded-md border border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800"
    >
      {dark ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}
