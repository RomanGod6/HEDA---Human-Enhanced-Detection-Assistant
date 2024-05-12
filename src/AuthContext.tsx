import React, { createContext, useContext, useState, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';


interface User {
    name: string;
    role: string;
    avatar?: string;
}

interface AuthContextType {
    isLoggedIn: boolean;
    user: User | null;
    setIsLoggedIn: React.Dispatch<React.SetStateAction<boolean>>;
    setUser: React.Dispatch<React.SetStateAction<User | null>>;
}

const AuthContext = createContext<AuthContextType>({
    isLoggedIn: false,
    user: null,
    setIsLoggedIn: () => { },
    setUser: () => { }
});

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [user, setUser] = useState<User | null>(null);

    useEffect(() => {
        const verifyToken = async () => {
            const token = localStorage.getItem('token');
            if (token) {
                try {
                    const decoded = jwtDecode(token) as any;
                    if (decoded.exp * 1000 > Date.now()) {
                        setIsLoggedIn(true);
                        setUser({
                            name: decoded.name,
                            role: decoded.role,
                            avatar: decoded.avatar,

                        });
                        console.log(user)
                    } else {
                        throw new Error("Please Log In To Continue");
                    }
                } catch (error) {
                    console.error('Token verification failed:', error);
                    setIsLoggedIn(false);
                    localStorage.removeItem('token');
                }
            }
        };

        verifyToken();
    }, []);

    // useEffect(() => {
    //     if (!isLoggedIn) {
    //         setUser(null);
    //     }
    // }, [isLoggedIn]);

    return (
        <AuthContext.Provider value={{ isLoggedIn, user, setIsLoggedIn, setUser }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);

