use std::{borrow::Cow, slice::Iter};

use serde::{Deserialize, Serialize};

use crate::utils::get_current_timestamp_in_secs;

#[allow(unused)]
#[rustfmt::skip]
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum Permission {
    AdministrativePriviliges = 0b1                  , // Lupyd Admin
    UserChatList             = 0b10                 , // Read Recent Chat List (not the chats, just the list of users chatted with)
    UpdateUserChat           = 0b100                , // ability to modify chats and chat keys
    CreateFile               = 0b1000               ,
    UpdatePost               = 0b10000              ,
    UpdateUser               = 0b100000             , // Manage Ads
    CreateGroup              = 0b1000000            ,
    UserTokensHandle         = 0b10000000           ,
    ManageAds                = 0b100000000          ,
}

impl Permission {
    #[inline(always)]
    pub const fn bit(self) -> u64 {
        self as u64
    }

    fn iter() -> Iter<'static, Self> {
        use Permission::*;
        [
            AdministrativePriviliges,
            UserChatList,
            UpdateUserChat,
            CreateFile,
            UpdatePost,
            UpdateUser,
            CreateGroup,
            UserTokensHandle,
            ManageAds,
        ]
        .iter()
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy)]
pub struct LupydTokenPermissions(pub u64);

impl LupydTokenPermissions {
    pub const fn has_all(&self, other: Self) -> bool {
        (other.value() & self.value()) == other.value()
    }

    pub const fn has_permission(&self, permission: Permission) -> bool {
        (self.value() & permission.bit()) != 0
    }

    pub const fn add_permission(self, permission: Permission) -> Self {
        Self(self.value() | permission.bit())
    }

    pub fn list_permissions(self) -> PermissionIter {
        PermissionIter::new(self)
    }

    pub const fn add_permissions(self, other: &Self) -> Self {
        Self(self.value() | other.value())
    }

    #[inline(always)]
    pub const fn value(&self) -> u64 {
        self.0
    }

    pub const LUPYD_USER: Self = Self(0)
        .add_permission(Permission::UpdateUser)
        .add_permission(Permission::UpdatePost)
        .add_permission(Permission::CreateFile)
        .add_permission(Permission::UserChatList)
        .add_permission(Permission::UpdateUserChat)
        .add_permission(Permission::UserTokensHandle)
        .add_permission(Permission::CreateGroup);
}
pub struct PermissionIter {
    all_permissions: Iter<'static, Permission>,
    permissions: LupydTokenPermissions,
}

impl PermissionIter {
    fn new(permissions: LupydTokenPermissions) -> Self {
        let all_permissions = Permission::iter();
        Self {
            all_permissions,
            permissions,
        }
    }
}

impl Iterator for PermissionIter {
    type Item = Permission;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(&permission) = self.all_permissions.next() {
                if self.permissions.has_permission(permission) {
                    return Some(permission);
                }
            } else {
                return None;
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct LupydToken<'a> {
    #[serde(rename = "uname")]
    pub username: Cow<'a, str>,

    #[serde(rename = "exp")]
    pub expiry: u64,

    #[serde(rename = "iat")]
    pub issued_at: u64,

    #[serde(rename = "aud")]
    pub audience: Cow<'a, str>,

    #[serde(rename = "iss")]
    pub issuer: Cow<'a, str>,

    pub permissions: LupydTokenPermissions,
}

impl<'a> LupydToken<'a> {
    pub fn jwt(
        username: Cow<'a, str>,
        issued_at: u64,
        expiry: u64,
        audience: Cow<'a, str>,
        permissions: LupydTokenPermissions,
    ) -> Self {
        // let issued_at = get_current_timestamp_in_secs();
        let issuer: &str = "lupyd.com";
        let issuer = Cow::Borrowed(issuer);

        Self {
            username,
            expiry,
            issued_at,
            audience,
            issuer,
            permissions,
        }
    }

    pub fn refresh(mut self) -> Option<Self> {
        let lifetime = self.expiry.checked_sub(self.issued_at)?;
        self.issued_at = get_current_timestamp_in_secs();
        self.expiry = self.issued_at.checked_add(lifetime)?;
        Some(self)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LupydRefreshToken<'a> {
    pub uid: i64,

    pub token: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub enum LupydApiScope {
    Authentication,   // Oauth Authenticate
    UserInformation,  // Access Username and Chat List
    AccessLikeGuest,  // Search Posts, Users
    FetchUserCredits, // Read User credits
    AcceptCredits,    // Request and accept user credits
}

impl LupydApiScope {
    #[inline(always)]
    pub const fn bit(self) -> u64 {
        1 << (self as u64)
    }

    pub fn iter() -> Iter<'static, Self> {
        use LupydApiScope::*;
        [
            Authentication,
            UserInformation,
            AcceptCredits,
            AccessLikeGuest,
            FetchUserCredits,
        ]
        .iter()
    }
}

#[derive(Serialize, Deserialize)]
pub struct LupydApiScopes(pub u64);

impl LupydApiScopes {
    pub const fn has_scope(&self, scope: LupydApiScope) -> bool {
        (self.value() & scope.bit()) != 0
    }

    pub const fn add_value(self, scope: LupydApiScope) -> Self {
        Self(self.value() | scope.bit())
    }

    pub const fn has_scopes(&self, other: &Self) -> bool {
        (self.value() & other.value()) == other.value()
    }

    pub const fn add_scopes(self, other: &Self) -> Self {
        Self(self.value() | other.value())
    }

    pub fn list_permissions(self) -> ApiScopesIter {
        ApiScopesIter::new(self)
    }

    #[inline(always)]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

pub struct ApiScopesIter {
    all_scopes: Iter<'static, LupydApiScope>,
    scopes: LupydApiScopes,
}

impl ApiScopesIter {
    fn new(scopes: LupydApiScopes) -> Self {
        let all_scopes = LupydApiScope::iter();
        Self { scopes, all_scopes }
    }
}

impl Iterator for ApiScopesIter {
    type Item = LupydApiScope;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(&scope) = self.all_scopes.next() {
                if self.scopes.has_scope(scope) {
                    return Some(scope);
                }
            } else {
                return None;
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct LupydApiKey {
    app_id: String,
    scopes: LupydApiScopes,
}
