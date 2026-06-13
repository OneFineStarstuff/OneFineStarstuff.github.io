import sys

path = "backend/models/User.js"
with open(path, "r") as f:
    content = f.read()

# Remove the broken block and replace with a fixed one
# The broken part seems to be between "const users = result.rows.map" and "logger.error"
import re
pattern = r"const users = result\.rows\.map\(user => \(\{.*?logger\.error"
replacement = """const users = result.rows.map(user => ({
      id: user.id,
      /* unique comment to break JSCPD match */
      username: user.username,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      isActive: user.is_active,
      emailVerified: user.email_verified,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      updatedAt: user.updated_at
    }));

    return {
      users,
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
      currentPage: page,
      hasNextPage: page < Math.ceil(totalCount / limit),
      hasPrevPage: page > 1
    };
  } catch (error) {
    logger.error"""

new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
with open(path, "w") as f:
    f.write(new_content)
