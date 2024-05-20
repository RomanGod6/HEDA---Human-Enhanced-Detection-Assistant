import React, { ReactNode } from 'react';

interface CardDataStatsProps {
  title: string;
  total: string;
  children?: ReactNode;
  description?: string;
  icon?: ReactNode;
}

const CardDataStats: React.FC<CardDataStatsProps> = ({
  title,
  total,
  children,
  description,
  icon,
}) => {
  return (
    <div className="rounded-lg border border-stroke bg-white p-6 shadow-lg dark:border-strokedark dark:bg-boxdark">
      <div className="flex items-center space-x-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-meta-2 dark:bg-meta-4">
          {icon || children}
        </div>
        <div className="flex flex-col">
          <h4 className="text-2xl font-bold text-black dark:text-white">
            {total}
          </h4>
          <span className="text-lg font-medium text-gray-500 dark:text-gray-300">{title}</span>
        </div>
      </div>

      {description && (
        <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">{description}</p>
      )}
    </div>
  );
};

export default CardDataStats;
