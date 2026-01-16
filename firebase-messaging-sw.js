importScripts("https://www.gstatic.com/firebasejs/10.7.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/10.7.0/firebase-messaging-compat.js");

firebase.initializeApp({
  apiKey: "AIzaSyBNfjs58Hnie6r-yEHAw11yPfvEct1eRKE",
  authDomain: "pzverse-chat.firebaseapp.com",
  projectId: "pzverse-chat",
  storageBucket: "pzverse-chat.firebasestorage.app",
  messagingSenderId: "401483325657",
  appId: "1:401483325657:web:1acf0edcccd6bd9d1e1ec8",
  measurementId: "G-ZF8SLL5JV6"
});

const messaging = firebase.messaging();

// Notificaciones cuando la web está cerrada o en segundo plano
messaging.onBackgroundMessage((payload) => {
  self.registration.showNotification(payload.notification.title, {
    body: payload.notification.body,
    icon: "/static/logo.png"
  });
});
