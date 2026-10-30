// Single place for demo routes, people and the chat copy the video depends on.
// People / groups / roles here must exist in the demo seeds (src/mocks).

/** The demo's emulated group video call (fullscreen call stage, Gremlin Hours). */
export const GROUP_CALL_ROUTE = '/groups/104?call=video&callView=full'

export const ROUTES = {
  dm: '/messages/sarah_chen',
  inbox: '/messages',
  kernelChannel: '/groups/101?c=1',
  designChannel: '/groups/102?c=1',
  respawnLobby: '/groups/104?c=1',
  steamDeck: '/groups/104?c=2',
}

/** DM scene: a real thread with Sarah, continued live */
export const CHAT = {
  dmUser: 'sarah_chen',
  dmName: 'Sarah',
  meAvatar: '/media/faces/alex.webp',
  // Sarah thinks out loud in short bursts
  // (continues the seed thread, which ends with Sarah asking about launch notes)
  burst: ['wait, before that', 'did you touch the sync code last night?', 'my laptop fan finally stopped screaming 😭', 'ok NOW tell me about the notes'],
  mine: ['I might have 👀', 'batched the writes. ~40% less cpu', 'shipping thursday. notes in your inbox tonight'],
  reply: 'you fixed my laptop by accident',
  reaction: '🔥',
}

/** Teams scene: Northbeam (startup) — new channel + a channel-level permission */
export const TEAMS = {
  group: 103,
  startChannel: 1,
  newChannel: 'launch-day',
  /** the role that can read but not post in the new channel */
  readOnlyRole: 'Contributor',
}

/** Guild scene: Gremlin Hours — roles + a role-badged raid chat */
export const GUILD = {
  group: 104,
  role: 'Raid Lead',
  /** permission switch toggled on for the role (GroupPermission bit) */
  grant: 32, // Manage Members
  grantLabel: 'Manage Members',
  chatChannel: 1,
  // senders' avatars and role badges are copied from their real rows in #lobby
  chat: [
    { from: 'FrostViper', text: 'raid tonight, 9pm', typing: 0.8 },
    { from: 'FrostViper', text: 'online by 8:50 pls', typing: 0.3 },
    { from: 'FrostViper', text: 'bring flasks. ALL of them', typing: 0.35 },
    { from: 'PixelBadger', text: 'I own one flask', typing: 0.5, reply: { who: 'FrostViper', text: 'bring flasks. ALL of them' } },
    { from: 'kai_gamer', text: "I'll run voice + share the map", typing: 0.45 },
    { from: 'NullPanther', text: '8:50 is ambitious but ok', typing: 0.5 },
  ],
}
