import React, { useState, useCallback, createContext, useContext } from 'react';
import type { ReactNode } from 'react';
import {
    encodeOtpRequest,
    encodeOtpVerify
} from './proto';
import { API_URL } from './config';

interface AuthState {
    isAuthenticated: boolean;
    email: string | null;
    token: string | null;
    isInitialLoading: boolean;
}

interface AuthContextType extends AuthState {
    loginWithEmail: (email: string, code: string, formId?: number) => Promise<void>;
    requestEmailCode: (email: string, formId?: number) => Promise<void>;
    logout: () => void;
    getAuthHeaders: () => Promise<Record<string, string>>;
    clearEmailAuth: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const UnifiedAuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [email, setEmail] = useState<string | null>(localStorage.getItem('noon_verified_email'));
    const [token, setToken] = useState<string | null>(localStorage.getItem('noon_email_token'));
    const [isLoading, setIsLoading] = useState(false);

    const clearEmailAuth = useCallback(() => {
        setEmail(null);
        setToken(null);
        localStorage.removeItem('noon_verified_email');
        localStorage.removeItem('noon_email_token');
    }, []);

    const logout = useCallback(() => {
        clearEmailAuth();
    }, [clearEmailAuth]);

    const requestEmailCode = async (emailAddr: string, formId: number = 0) => {
        setIsLoading(true);
        try {
            const encoded = encodeOtpRequest({ email: emailAddr, formId });
            const response = await fetch(`${API_URL}/email/request_otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                // @ts-expect-error
                body: encoded,
            });
            if (!response.ok) {
                throw new Error('Failed to send verification email');
            }
        } finally {
            setIsLoading(false);
        }
    };

    const loginWithEmail = async (emailAddr: string, code: string, formId: number = 0) => {
        setIsLoading(true);
        try {
            const encoded = encodeOtpVerify({ email: emailAddr, code, formId });
            const response = await fetch(`${API_URL}/email/verify_otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                // @ts-expect-error
                body: encoded,
            });
            if (!response.ok) {
                throw new Error('Invalid verification code');
            }
            const newToken = await response.text();
            setEmail(emailAddr);
            setToken(newToken);
            localStorage.setItem('noon_verified_email', emailAddr);
            localStorage.setItem('noon_email_token', newToken);
        } finally {
            setIsLoading(false);
        }
    };

    const getAuthHeaders = useCallback(async () => {
        if (token) {
            return { 'Authorization': `EmailOnly ${token}` };
        }
        return {};
    }, [token]);

    const value: AuthContextType = {
        isAuthenticated: !!token,
        email: email,
        token: token,
        isInitialLoading: isLoading,
        loginWithEmail,
        requestEmailCode,
        logout,
        getAuthHeaders: getAuthHeaders as () => Promise<Record<string, string>>,
        clearEmailAuth
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useUnifiedAuth = () => {
    const context = useContext(AuthContext);
    if (!context) throw new Error('useUnifiedAuth must be used within UnifiedAuthProvider');
    return context;
};
