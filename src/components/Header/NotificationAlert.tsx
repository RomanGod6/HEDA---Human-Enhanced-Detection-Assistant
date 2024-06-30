import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { AppNotification } from '../../../global'; // Adjust the path as necessary
import './styles.css'; // Import the CSS file

interface NotificationAlertProps {
    notifications: AppNotification[];
    onClearAll: () => void;
}

const NotificationAlert: React.FC<NotificationAlertProps> = ({ notifications, onClearAll }) => {
    const [showAll, setShowAll] = useState(false);

    const handleViewAll = () => {
        setShowAll(true);
    };

    const displayedNotifications = showAll ? notifications : notifications.slice(-10);

    return (
        <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {displayedNotifications.length === 0 ? (
                <div className="alert alert-info">No notifications</div>
            ) : (
                displayedNotifications.map((notification, index) => (
                    <Link to={`/notification/${notification.log_id}`} key={index} className="notification-card">
                        <div className="notification-title">Malicious Packet Detected!</div>
                        <div className="notification-details">
                            Log ID: {notification.log_id}, Timestamp: {new Date(notification.notification_timestamp).toLocaleString()}
                        </div>
                    </Link>
                ))
            )}
            {!showAll && notifications.length > 10 && (
                <button className="btn btn-link" onClick={handleViewAll}>
                    View All
                </button>
            )}
            {notifications.length > 0 && (
                <button className="btn btn-link" onClick={onClearAll}>
                    Clear All
                </button>
            )}
        </div>
    );
};

export default NotificationAlert;
