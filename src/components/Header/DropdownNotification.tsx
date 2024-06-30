import React, { useState, useEffect } from 'react';
import NotificationAlert from './NotificationAlert';
import { AppNotification } from '../../../global'; // Adjust the path as necessary
import './styles.css'; // Import the CSS file
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBell } from '@fortawesome/free-solid-svg-icons';

const DropdownNotification: React.FC = () => {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);

  const fetchNotifications = async () => {
    const result = await window.electron.fetchNotifications();
    setNotifications(result);
  };

  const markAllAsViewed = async () => {
    await window.electron.markAllNotificationsAsViewed();
    fetchNotifications(); // Refresh notifications after marking all as viewed
  };

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 5000); // Poll every 5 seconds

    return () => clearInterval(interval); // Cleanup interval on component unmount
  }, []);

  return (
    <div className="relative">
      <button onClick={() => setDropdownOpen(!dropdownOpen)} className="flex items-center gap-4 cursor-pointer relative">
        <span className="hidden text-right lg:block">
          <span className="block text-sm font-medium text-black dark:text-white">
            Notifications
          </span>
        </span>
        <div className="badge-container">
          <FontAwesomeIcon icon={faBell} className="fill-current h-6 w-6" />
          {notifications.length > 0 && (
            <span className="badge">
              {notifications.length}
            </span>
          )}
        </div>
      </button>

      {dropdownOpen && (
        <div className="absolute right-0 mt-4 w-48 bg-white shadow-md">
          <div className="p-2">
            <button onClick={markAllAsViewed} className="w-full text-center text-sm text-blue-600">
              Mark All as Viewed
            </button>
          </div>
          <NotificationAlert notifications={notifications} onNotificationClick={markAllAsViewed} />
        </div>
      )}
    </div>
  );
};

export default DropdownNotification;
