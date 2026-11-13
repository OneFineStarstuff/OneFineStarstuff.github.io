import { Band } from '../types/gien';

const STYLES: Record<Band, string> = {
  GREEN: 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900 dark:text-green-200',
  AMBER: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-900 dark:text-amber-200',
  RED: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900 dark:text-red-200'
};

export default function BandBadge({ band }: { band: Band }) {
  return (
    <span className={'inline-block px-2 py-0.5 rounded border text-xs font-semibold ' + STYLES[band]}>
      {band}
    </span>
  );
}
