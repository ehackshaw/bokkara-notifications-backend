// Approved Bokkara Android push notification types.
// Event delivery and one-time eligibility are enforced by the caller / event endpoint.
export const EVENTS = Object.freeze({
  welcome: {
    title: 'Welcome to Bokkara',
    body: 'Welcome to Bokkara! Your next stay starts here.',
    path: '/pages/my-account'
  },
  membership_invitation: {
    title: 'Become a Bokkara Member',
    body: 'Unlock exclusive member rates and benefits with a Bokkara membership.',
    path: '/pages/membership'
  },
  booking_received: {
    title: 'Booking request received',
    body: "We've received your booking request and are contacting the property to confirm your stay.",
    path: '/pages/my-account'
  },
  booking_confirmed: {
    title: 'Your booking is confirmed',
    body: 'Your booking has been confirmed. Open Bokkara to view your reservation.',
    path: '/pages/my-account'
  },
  booking_adjusted: {
    title: 'Your booking was adjusted',
    body: 'Your booking details have been updated. Open Bokkara to view the latest information.',
    path: '/pages/my-account'
  }
});
