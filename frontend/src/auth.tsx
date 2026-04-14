import React, { useState, useCallback, createContext, useContext } from 'react';
import type { ReactNode } from 'react';
import {
    encodeOtpRequest,
    encodeOtpVerify
} from './proto';

interface AuthState {
    isAuthenticated: boolean;
    email: string | null;
    token: string | null;
    isAuth0: boolean;
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

export const UnifiedAuthProvider: React.FC<{ children: ReactNode, auth0: any }> = ({ children, auth0 }) => {
    const [email, setEmail] = useState<string | null>(localStorage.getItem('noon_verified_email'));
    const [token, setToken] = useState<string | null>(localStorage.getItem('noon_email_token'));

    const clearEmailAuth = useCallback(() => {
        setEmail(null);
        setToken(null);
        localStorage.removeItem('noon_verified_email');
        localStorage.removeItem('noon_email_token');
    }, []);

    const logout = useCallback(() => {
        if (auth0.isAuthenticated) {
            auth0.logout({ logoutParams: { returnTo: window.location.origin } });
        }
        clearEmailAuth();
    }, [auth0, clearEmailAuth]);

    const requestEmailCode = async (emailAddr: string, formId: number = 0) => {
        const encoded = encodeOtpRequest({ email: emailAddr, formId });
        const response = await fetch('http://localhost:39210/email/request_otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/octet-stream' },
            // @ts-expect-error
            body: encoded,
        });
        if (!response.ok) {
            throw new Error('Failed to send verification email');
        }
    };

    const loginWithEmail = async (emailAddr: string, code: string, formId: number = 0) => {
        const encoded = encodeOtpVerify({ email: emailAddr, code, formId });
        const response = await fetch('http://localhost:39210/email/verify_otp', {
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
    };

    const getAuthHeaders = useCallback(async () => {
        if (auth0.isAuthenticated) {
            try {
                const auth0Token = await auth0.getAccessTokenSilently();
                return { 'Authorization': `Bearer ${auth0Token}` };
            } catch (e) {
                console.error("Auth0 token fetch failed", e);
            }
        }
        if (token) {
            return { 'Authorization': `EmailOnly ${token}` };
        }
        return {};
    }, [auth0.isAuthenticated, auth0.getAccessTokenSilently, token]);

    const value: AuthContextType = {
        isAuthenticated: auth0.isAuthenticated || !!token,
        email: auth0.user?.email || email,
        token: token,
        isAuth0: auth0.isAuthenticated,
        isInitialLoading: auth0.isLoading,
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
