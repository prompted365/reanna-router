# Authentication & Authorization

## Overview

REanna Router uses Auth0 for authentication and authorization. This document describes how to set up Auth0 for use with the application and how to integrate it with your frontend.

## Auth0 Setup

1. Create an Auth0 account and tenant
2. Create a new API with the following settings:
   - Name: REanna Router API
   - Identifier: https://api.reanna-router.com (or your custom domain)
   - Signing Algorithm: RS256

3. Define the following scopes in your API settings:
   - `read:tours` - Ability to view tours
   - `create:tours` - Ability to create new tours
   - `update:tours` - Ability to update existing tours
   - `read:visits` - Ability to view property visits
   - `update:visits` - Ability to update property visits
   - `read:tasks` - Ability to view tasks
   - `update:tasks` - Ability to update tasks
   - `read:feedback` - Ability to view feedback
   - `create:feedback` - Ability to create feedback
   - `admin:system` - Administrative access to system settings

4. Create the following roles:
   - Agent
   - Admin

5. Assign permissions to roles as follows:

### Agent Role
   - `read:tours` (own tours only)
   - `create:tours`
   - `update:tours` (own tours only)
   - `read:visits` (related to own tours)
   - `update:visits` (related to own tours)
   - `read:tasks` (related to own tours)
   - `update:tasks` (related to own tours)
   - `read:feedback` (related to own tours)

### Admin Role
   - All permissions

6. Create a Rule to include roles in the access token:

```javascript
function (user, context, callback) {
  const namespace = 'https://api.reanna-router.com';
  const assignedRoles = (context.authorization || {}).roles || [];
  
  let permissions = [];
  // Map permissions based on roles
  if (assignedRoles.includes('admin')) {
    permissions = [
      'read:tours', 'create:tours', 'update:tours',
      'read:visits', 'update:visits',
      'read:tasks', 'update:tasks',
      'read:feedback', 'create:feedback',
      'admin:system'
    ];
  } else if (assignedRoles.includes('agent')) {
    permissions = [
      'read:tours', 'create:tours', 'update:tours',
      'read:visits', 'update:visits',
      'read:tasks', 'update:tasks',
      'read:feedback'
    ];
  }
  
  context.accessToken[`${namespace}/permissions`] = permissions;
  callback(null, user, context);
}
```

## Integration with Frontend

Your frontend should use the Auth0 SDK to authenticate users and obtain access tokens. When making requests to the REanna Router API, include the access token in the Authorization header as a Bearer token:

```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

## Testing Authentication

You can test authentication by creating a test user in Auth0 and assigning it to the Agent or Admin role. Then use the Auth0 Authentication API to obtain an access token for this user and include it in your requests to the REanna Router API.

## Security Considerations

- All API endpoints are protected with JWT validation
- Access tokens are short-lived (default 1 hour)
- Use refresh tokens for long-lived sessions
- Implement proper CORS settings in your API
- Always validate audience and issuer in JWT tokens
