// Firebase Cloud Messaging Service Worker
// This service worker handles push notifications from Firebase Cloud Messaging

importScripts('https://www.gstatic.com/firebasejs/9.22.1/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/9.22.1/firebase-messaging-compat.js');

// Initialize Firebase in service worker
const firebaseConfig = {
  apiKey: "AIzaSyDOwZzQ4b3uNQzfFw6X3dfPEBuJFC7ZZyQ",
  authDomain: "datasell-a3f57.firebaseapp.com",
  databaseURL: "https://datasell-a3f57-default-rtdb.europe-west1.firebasedatabase.app",
  projectId: "datasell-a3f57",
  storageBucket: "datasell-a3f57.firebasestorage.app",
  messagingSenderId: "717867799921",
  appId: "1:717867799921:web:2a0c6e675dd3c598e012d0"
};

firebase.initializeApp(firebaseConfig);
const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
  console.log('Received background message:', payload);
  
  const notificationTitle = payload.notification?.title || 'DataSell';
  const notificationOptions = {
    body: payload.notification?.body || 'You have a new notification',
    icon: payload.notification?.image || '/images/app-icon.png',
    badge: '/images/app-icon.png',
    tag: 'datasell-notification',
    requireInteraction: false,
    data: payload.data || {}
  };

  // Show notification
  self.registration.showNotification(notificationTitle, notificationOptions);
});

// Handle notification click
self.addEventListener('notificationclick', (event) => {
  console.log('Notification clicked:', event.notification);
  event.notification.close();
  
  // Open the app or focus existing window
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Check if there's already a window open
      for (let i = 0; i < clientList.length; i++) {
        const client = clientList[i];
        if (client.url === '/' && 'focus' in client) {
          return client.focus();
        }
      }
      // If no window open, open a new one
      if (clients.openWindow) {
        return clients.openWindow('/');
      }
    })
  );
});

// Handle notification close
self.addEventListener('notificationclose', (event) => {
  console.log('Notification closed:', event.notification);
});
