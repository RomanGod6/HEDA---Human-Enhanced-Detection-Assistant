import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { AppNotification, PacketDetails } from '../../global'; // Adjust the path as necessary
import DefaultLayout from '../layout/DefaultLayout'; // Ensure the correct path
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './NotificationDetail.css'; // Optional: CSS for additional custom styling

interface NotificationDetails {
    notification: AppNotification;
    packetDetails: PacketDetails;
}

const NotificationDetail: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const [details, setDetails] = useState<NotificationDetails | null>(null);

    useEffect(() => {
        const fetchNotification = async () => {
            if (id) {
                try {
                    const result = await window.electron.fetchNotificationById(parseInt(id, 10));
                    console.log('Fetched Notification:', result);
                    setDetails(result);
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
                await window.electron.updateNotificationStatus(parseInt(id, 10), true);
                toast.success('Packet confirmed as malicious!');
            } catch (error) {
                console.error('Error updating notification status:', error);
                toast.error('Failed to update status. Please try again.');
            }
        }
    };

    const handleConfirmNotMalicious = async () => {
        if (id) {
            try {
                await window.electron.updateNotificationStatus(parseInt(id, 10), false);
                toast.success('Packet confirmed as not malicious!');
            } catch (error) {
                console.error('Error updating notification status:', error);
                toast.error('Failed to update status. Please try again.');
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

    if (!details) {
        return <div className="text-center text-white">Loading...</div>;
    }

    return (
        <DefaultLayout>
            <div className="notification-detail max-w-3xl mx-auto p-6 bg-gray-800 text-white rounded-lg shadow-lg">
                <h1 className="text-2xl font-bold mb-4">Malicious Packet Details</h1>
                <div className="mb-4">
                    <p><strong>Log ID:</strong> {details.notification.log_id}</p>
                    <p><strong>Timestamp:</strong> {new Date(details.notification.notification_timestamp).toLocaleString()}</p>
                    <p><strong>Source IP:</strong> {details.packetDetails.src_ip}</p>
                    <p><strong>Destination IP:</strong> {details.packetDetails.dst_ip}</p>
                    <p><strong>Source Port:</strong> {details.packetDetails.src_port}</p>
                    <p><strong>Destination Port:</strong> {details.packetDetails.dst_port}</p>
                    <p><strong>Protocol:</strong> {details.packetDetails.protocol}</p>
                    <p><strong>Payload:</strong> <code className="block whitespace-pre-wrap">{hexToAscii(details.packetDetails.payload)}</code></p>
                    <p><strong>Details:</strong> {details.notification.details}</p>
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
            <ToastContainer />
        </DefaultLayout>
    );
};

export default NotificationDetail;
