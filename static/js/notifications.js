const notificationsDropdown = document.getElementById('notificationsDropdown');
const notificationsList = document.getElementById('notificationsList');
const notificationsToggle = document.getElementById('notifications-toggle');
const iconBellRead = document.getElementById('icon-bell-read');
const iconBellUnread = document.getElementById('icon-bell-unread');

async function fetchNotifications() {
    try {
        const response = await fetch('/api/notifications', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const notifications = await response.json();
        updateNotifications(notifications);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        notificationsList.innerHTML = `
            <div data-value="" aria-disabled="true">
                Error loading notifications
            </div>
        `;
    }
}

function updateNotifications(notifications) {
    const unreadCount = notifications.filter(n => !n.is_read).length;
    iconBellUnread.style.display = unreadCount > 0 ? 'block' : 'none';
    iconBellRead.style.display = unreadCount > 0 ? 'none' : 'block';

    if (notifications.length === 0) {
        notificationsList.innerHTML = `
            <div data-value="" aria-disabled="true">
                No notifications
            </div>
        `;
        return;
    }

    const dismissButton = `
        <button id="dismiss-all-notifications" class="button delete">
            Dismiss All
        </button>
    `;

    notificationsList.innerHTML = dismissButton + notifications.map(notification => {
        const date = new Date(notification.created_at).toLocaleString();
        let actions = '';
        if (notification.notification_type === 'friend_request' && notification.related_username) {
            actions = `
                <div style="margin-top: 8px;">
                    <button class="button save accept-friend-request" data-username="${notification.related_username}">
                        Accept
                    </button>
                    <button class="button delete decline-friend-request" data-username="${notification.related_username}">
                        Decline
                    </button>
                </div>
            `;
        }
        return `
            <div data-value="${notification.notification_id}" role="option" style="${notification.is_read ? '' : 'font-weight: bold;'}">
                ${notification.message}
                <br>
                <small style="color: var(--accent-text-color);">${date}</small>
                ${actions}
            </div>
        `;
    }).join('');

    document.querySelectorAll('.accept-friend-request').forEach(button => {
        button.addEventListener('click', () => handleFriendRequest(button.dataset.username, 'accept'));
    });
    document.querySelectorAll('.decline-friend-request').forEach(button => {
        button.addEventListener('click', () => handleFriendRequest(button.dataset.username, 'decline'));
    });

    const dismissAllBtn = document.getElementById('dismiss-all-notifications');
    if (dismissAllBtn) {
        dismissAllBtn.addEventListener('click', dismissAllNotifications);
    }
}

async function handleFriendRequest(username, action) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (!csrfToken) {
        console.error('CSRF token not found in meta tag');
        alert(`Failed to ${action} friend request. CSRF token missing.`);
        return;
    }

    try {
        const response = await fetch(`/friend-request/respond/${username}/${action}`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-Token': csrfToken,
            },
            body: JSON.stringify({ csrf_token: csrfToken }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
        }

        const result = await response.json();
        console.log(`Friend request ${action}ed:`, result.message);
        await fetchNotifications();
    } catch (error) {
        console.error(`Error ${action}ing friend request for ${username}:`, error);
        alert(`Failed to ${action} friend request. Error: ${error.message}`);
    }
}

async function dismissAllNotifications() {
    try {
        const response = await fetch('/api/notifications/dismiss_all', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        console.log(result.message);

        await fetchNotifications();
    } catch (error) {
        console.error('Error dismissing all notifications:', error);
        alert('Failed to dismiss all notifications.');
    }
}

async function toggleNotifications(event) {
    event.stopPropagation();
    const isExpanded = notificationsToggle.getAttribute('aria-expanded') === 'true';
    notificationsToggle.setAttribute('aria-expanded', !isExpanded);
    notificationsList.style.display = isExpanded ? 'none' : 'block';
    if (!isExpanded) {
        await fetchNotifications();
        await markNotificationsRead();
    }
}

async function markNotificationsRead() {
    try {
        const response = await fetch('/api/notifications/read', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Accept': 'application/json',
            },
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        await fetchNotifications();
    } catch (error) {
        console.error('Error marking notifications as read:', error);
    }
}

document.addEventListener('click', (event) => {
    if (!notificationsDropdown.contains(event.target)) {
        notificationsToggle.setAttribute('aria-expanded', 'false');
        notificationsList.style.display = 'none';
    }
});

notificationsToggle.addEventListener('click', toggleNotifications);

document.addEventListener('DOMContentLoaded', () => {
    fetchNotifications();
});
