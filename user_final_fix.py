import sys

path = "backend/models/User.js"
with open(path, "r") as f:
    lines = f.readlines()

# Clean up any mess from previous seds
# We want the header, the helper, and then the rest of the file starting from "/**"
header = [
    "/**\n",
    " * User Model\n",
    " * Handles user CRUD operations with encrypted sensitive data\n",
    " */\n",
    "\n",
    "import { query, transaction } from '../config/database.js';\n",
    "import { encryptField, decryptField } from '../utils/encryption.js';\n",
    "import logger from '../utils/logger.js';\n",
    "import _crypto from 'crypto';\n",
    "\n",
    "const _mapUser = (user) => ({\n",
    "  id: user.id,\n",
    "  username: user.username,\n",
    "  email: user.email,\n",
    "  firstName: user.first_name,\n",
    "  lastName: user.last_name,\n",
    "  role: user.role,\n",
    "  isActive: user.is_active,\n",
    "  emailVerified: user.email_verified,\n",
    "  lastLogin: user.last_login,\n",
    "  createdAt: user.created_at,\n",
    "  updatedAt: user.updated_at\n",
    "});\n"
]

content_lines = []
found_start = False
for line in lines:
    if line.startswith("/**") and "Create a new user" in line:
        found_start = True
    if found_start:
        content_lines.append(line)

with open(path, "w") as f:
    f.writelines(header)
    f.write("\n")
    f.writelines(content_lines)

# Also fix the broken map usage in the file
with open(path, "r") as f:
    content = f.read()

import re
# Fix the two mapping blocks to use _mapUser
# Block 1
content = re.sub(r"return \{\s+id: user\.id,\s+username: user\.username,.*?bio: user\.bio\s+\};", "return { ..._mapUser(user), preferences: user.preferences || {}, avatarUrl: user.avatar_url, bio: user.bio };", content, flags=re.DOTALL)
# Block 2
content = re.sub(r"const users = result\.rows\.map\(user => \(\{.*?\}\)\);", "const users = result.rows.map(_mapUser);", content, flags=re.DOTALL)

with open(path, "w") as f:
    f.write(content)
