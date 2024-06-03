import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { AppNotification, PacketDetails } from '../../global'; // Adjust the path as necessary
import DefaultLayout from '../layout/DefaultLayout'; // Ensure the correct path
import './NotificationDetail.css'; // Optional: CSS for additional custom styling

const NotificationDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const [notification, setNotification] = useState<AppNotification | null>(null);
    const [packetDetails, setPacketDetails] = useState<PacketDetails | null>(null);

    useEffect(() => {
        const fetchNotification = async () => {
            if (id) {
                try {
                    const result = await window.electron.fetchNotificationById(parseInt(id, 10));
                    console.log('Fetched Notification:', result);
                    setNotification(result.notification);
                    setPacketDetails(result.packetDetails);
                } catch (error) {
                    console.error('Error fetching notification:', error);
                }
            }
        };

        fetchNotification();
    }, [id]);

    const handleConfirmMalicious = async () => {
        if (id) {
            try {
                await window.electron.updateNotificationStatus(parseInt(id, 10), 'malicious');
                // Update UI or show a message
            } catch (error) {
                console.error('Error updating notification status:', error);
            }
        }
    };

    const handleConfirmNotMalicious = async () => {
        if (id) {
            try {
                await window.electron.updateNotificationStatus(parseInt(id, 10), 'not_malicious');
                // Update UI or show a message
            } catch (error) {
                console.error('Error updating notification status:', error);
            }
        }
    };

    const hexToAscii = (hex: string): string => {
        try {
            // Try to decode the hex string as UTF-8
            const utf8Decoder = new TextDecoder("utf-8");
            const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
            const decodedString = utf8Decoder.decode(bytes);

            // If the string contains only printable ASCII characters, return it
            if (/^[\x20-\x7E]*$/.test(decodedString)) {
                return decodedString;
            }
        } catch (e) {
            // Fallback if the decoding fails
            console.error('Failed to decode as UTF-8:', e);
        }

        // Fallback: replace non-printable characters with dots
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            const hexByte = hex.substr(i, 2);
            const charCode = parseInt(hexByte, 16);
            if (charCode >= 32 && charCode <= 126) {
                str += String.fromCharCode(charCode);
            } else {
                str += '.';
            }
        }
        return str;
    };

    if (!notification || !packetDetails) {
        return <div className="text-center text-white">Loading...</div>;
    }

    return (
        <DefaultLayout>
            <div className="notification-detail max-w-3xl mx-auto p-6 bg-gray-800 text-white rounded-lg shadow-lg">
                <h1 className="text-2xl font-bold mb-4">Malicious Packet Details</h1>
                <div className="mb-4">
                    <p><strong>Log ID:</strong> {notification.log_id}</p>
                    <p><strong>Timestamp:</strong> {new Date(notification.notification_timestamp).toLocaleString()}</p>
                    <p><strong>Source IP:</strong> {packetDetails.src_ip}</p>
                    <p><strong>Destination IP:</strong> {packetDetails.dst_ip}</p>
                    <p><strong>Source Port:</strong> {packetDetails.src_port}</p>
                    <p><strong>Destination Port:</strong> {packetDetails.dst_port}</p>
                    <p><strong>Protocol:</strong> {packetDetails.protocol}</p>
                    <p><strong>Payload:</strong> <code className="block whitespace-pre-wrap">{hexToAscii(packetDetails.payload)}</code></p>
                    <p><strong>Details:</strong> {notification.details}</p>
                </div>
                <div className="flex space-x-4">
                    <button onClick={handleConfirmMalicious} className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700">
                        Confirm Malicious
                    </button>
                    <button onClick={handleConfirmNotMalicious} className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
                        Confirm Not Malicious
                    </button>
                </div>
            </div>
        </DefaultLayout>
    );
};

export default NotificationDetail;
