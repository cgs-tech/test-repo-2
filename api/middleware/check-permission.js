const User = require("../models/user");

// Predefined permission constants for easy use
const PERMISSIONS = {
  // User permissions
  READ_OWN: 'read:own',
  UPDATE_OWN: 'update:own',
  DELETE_OWN: 'delete:own',
  
  // Product permissions
  READ_PRODUCTS: 'read:products',
  CREATE_PRODUCTS: 'create:products',
  UPDATE_PRODUCTS: 'update:products',
  DELETE_PRODUCTS: 'delete:products',
  
  // Order permissions
  READ_ORDERS: 'read:orders',
  CREATE_ORDERS: 'create:orders',
  UPDATE_ORDERS: 'update:orders',
  DELETE_ORDERS: 'delete:orders',
  
  // Admin permissions
  READ_ALL: 'read:all',
  CREATE_ALL: 'create:all',
  UPDATE_ALL: 'update:all',
  DELETE_ALL: 'delete:all',
  
  // User management
  MANAGE_USERS: 'manage:users',
  ASSIGN_ROLES: 'assign:roles'
};

// Role-based permission mapping
const ROLE_PERMISSIONS = {
  user: [PERMISSIONS.READ_OWN, PERMISSIONS.UPDATE_OWN],
  moderator: [
    PERMISSIONS.READ_OWN, 
    PERMISSIONS.UPDATE_OWN, 
    PERMISSIONS.READ_PRODUCTS, 
    PERMISSIONS.CREATE_PRODUCTS, 
    PERMISSIONS.UPDATE_PRODUCTS
  ],
  manager: [
    PERMISSIONS.READ_ALL, 
    PERMISSIONS.CREATE_ALL, 
    PERMISSIONS.UPDATE_ALL, 
    PERMISSIONS.READ_ORDERS, 
    PERMISSIONS.UPDATE_ORDERS
  ],
  admin: ['*'], // Admin has all permissions
  superadmin: ['*'] // Superadmin has all permissions
};

// Admin roles that bypass permission checks
const ADMIN_ROLES = ['admin', 'superadmin'];

/**
 * Permission check middleware factory
 * @param {string|Array} requiredPermissions - Required permission(s) for the route
 * @param {Object} options - Options object
 * @param {string} options.resource - Resource name for resource-based permissions
 * @param {boolean} options.allowOwner - Allow resource owner access
 * @returns {Function} Express middleware function
 */
const checkPermission = (requiredPermissions, options = {}) => {
  const { resource = null, allowOwner = false } = options;
  
  return async (req, res, next) => {
    try {
      // Validate authentication
      const authError = validateAuthentication(req);
      if (authError) {
        return res.status(401).json(authError);
      }

      // Fetch user from database
      const user = await getUserById(req.userData.userId);
      if (!user) {
        return res.status(401).json({
          message: "User not found"
        });
      }

      // Normalize permissions to array
      const permissions = normalizePermissions(requiredPermissions);

      // Check permissions
      const hasPermission = await checkUserPermissions(user, permissions, { resource, allowOwner, req });

      if (!hasPermission) {
        return res.status(403).json({
          message: "Insufficient permissions",
          required: permissions,
          resource: resource || 'general'
        });
      }

      // Attach permission context to request
      attachPermissionContext(req, user, permissions, resource);

      next();
    } catch (error) {
      return res.status(500).json({
        message: "Permission check failed",
        error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  };
};

/**
 * Validate user authentication
 * @param {Object} req - Express request object
 * @returns {Object|null} Error object or null if valid
 */
function validateAuthentication(req) {
  if (!req.userData || !req.userData.userId) {
    return { message: "Authentication required" };
  }
  return null;
}

/**
 * Get user by ID with error handling
 * @param {string} userId - User ID
 * @returns {Promise<Object|null>} User object or null
 */
async function getUserById(userId) {
  try {
    return await User.findById(userId);
  } catch (error) {
    throw new Error(`Failed to fetch user: ${error.message}`);
  }
}

/**
 * Normalize permissions to array format
 * @param {string|Array} permissions - Permission(s) to normalize
 * @returns {Array} Array of permissions
 */
function normalizePermissions(permissions) {
  return Array.isArray(permissions) ? permissions : [permissions];
}

/**
 * Attach permission context to request object
 * @param {Object} req - Express request object
 * @param {Object} user - User object
 * @param {Array} permissions - Granted permissions
 * @param {string} resource - Resource name
 */
function attachPermissionContext(req, user, permissions, resource) {
  req.permissions = {
    user: {
      id: user._id,
      email: user.email,
      role: user.role
    },
    granted: permissions,
    resource: resource || 'general'
  };
}

/**
 * Check if user has required permissions
 * @param {Object} user - User object from database
 * @param {Array} requiredPermissions - Array of required permissions
 * @param {Object} options - Options object
 * @param {string} options.resource - Resource name
 * @param {boolean} options.allowOwner - Allow resource owner access
 * @param {Object} options.req - Express request object
 * @returns {Promise<boolean>} Whether user has permissions
 */
async function checkUserPermissions(user, requiredPermissions, options = {}) {
  const { resource, allowOwner, req } = options;

  // Admin bypass
  if (isAdmin(user)) {
    return true;
  }

  // Check resource ownership if allowed
  if (allowOwner && resource === 'own' && hasResourceOwnership(user, req)) {
    return true;
  }

  // Check explicit user permissions
  if (hasExplicitPermissions(user, requiredPermissions)) {
    return true;
  }

  // Check role-based permissions
  if (hasRolePermissions(user, requiredPermissions)) {
    return true;
  }

  return false;
}

/**
 * Check if user is admin
 * @param {Object} user - User object
 * @returns {boolean} Whether user is admin
 */
function isAdmin(user) {
  return user.role && ADMIN_ROLES.includes(user.role);
}

/**
 * Check if user has resource ownership
 * @param {Object} user - User object
 * @param {Object} req - Express request object
 * @returns {boolean} Whether user owns the resource
 */
function hasResourceOwnership(user, req) {
  const resourceId = req.params.userId || req.params.id;
  return resourceId && resourceId === user._id.toString();
}

/**
 * Check if user has explicit permissions
 * @param {Object} user - User object
 * @param {Array} requiredPermissions - Required permissions
 * @returns {boolean} Whether user has explicit permissions
 */
function hasExplicitPermissions(user, requiredPermissions) {
  if (!user.permissions || !Array.isArray(user.permissions)) {
    return false;
  }

  return requiredPermissions.every(permission => 
    user.permissions.includes(permission)
  );
}

/**
 * Check if user's role has required permissions
 * @param {Object} user - User object
 * @param {Array} requiredPermissions - Required permissions
 * @returns {boolean} Whether role has permissions
 */
function hasRolePermissions(user, requiredPermissions) {
  if (!user.role) {
    return false;
  }

  const rolePermissions = ROLE_PERMISSIONS[user.role] || [];

  // Check for wildcard permission
  if (rolePermissions.includes('*')) {
    return true;
  }

  // Check if user has all required permissions
  return requiredPermissions.every(permission => 
    rolePermissions.includes(permission)
  );
}

/**
 * Create a permission middleware with specific permissions
 * @param {Array} permissions - Required permissions
 * @param {Object} options - Additional options
 * @returns {Function} Express middleware
 */
function requirePermissions(permissions, options = {}) {
  return checkPermission(permissions, options);
}

/**
 * Create a middleware that allows access to resource owners
 * @param {string|Array} permissions - Required permissions for non-owners
 * @returns {Function} Express middleware
 */
function requireOwnershipOrPermissions(permissions) {
  return checkPermission(permissions, { resource: 'own', allowOwner: true });
}

/**
 * Create a middleware for admin-only routes
 * @returns {Function} Express middleware
 */
function requireAdmin() {
  return (req, res, next) => {
    if (!req.userData?.userId) {
      return res.status(401).json({ message: "Authentication required" });
    }

    User.findById(req.userData.userId)
      .then(user => {
        if (!user || !isAdmin(user)) {
          return res.status(403).json({ message: "Admin access required" });
        }
        next();
      })
      .catch(error => {
        res.status(500).json({ 
          message: "Permission check failed",
          error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
      });
  };
}

module.exports = {
  checkPermission,
  requirePermissions,
  requireOwnershipOrPermissions,
  requireAdmin,
  PERMISSIONS,
  ROLE_PERMISSIONS
};
