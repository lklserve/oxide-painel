
function calculateDuration(expires, now) {
    const diffMs = expires - now;
    if (diffMs < 0) return "Expired";

    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

    return {
        days: diffDays,
        hours: diffHours,
        minutes: diffMinutes,
        formatted: `${diffDays}d ${diffHours}h ${diffMinutes}m`
    };
}

// Tests
const now = new Date();
const tests = [
    { name: "2 days, 5 hours, 30 mins", offset: (2 * 24 * 60 * 60 * 1000) + (5 * 60 * 60 * 1000) + (30 * 60 * 1000) },
    { name: "0 days, 1 hour, 0 mins", offset: (1 * 60 * 60 * 1000) },
    { name: "0 days, 0 hours, 59 mins", offset: (59 * 60 * 1000) },
    { name: "30 days", offset: (30 * 24 * 60 * 60 * 1000) }
];

tests.forEach(t => {
    const expires = new Date(now.getTime() + t.offset);
    const result = calculateDuration(expires, now);
    console.log(`Test: ${t.name} -> Result: ${result.formatted} (Expectation matches?)`);
    console.log(JSON.stringify(result));
});
