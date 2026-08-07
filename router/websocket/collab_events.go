package websocket

import (
	"github.com/mythicalltd/featherwings/server/collab"
)

const (
	FileCollabSubscribeEvent    = Event(collab.EventSubscribe)
	FileCollabUnsubscribeEvent  = Event(collab.EventUnsubscribe)
	FileCollabUpdateEvent       = Event(collab.EventUpdateIn)
	FileCollabAwarenessEvent    = Event(collab.EventAwarenessIn)
	FileCollabSaveEvent         = Event(collab.EventSave)
	FileCollabReloadEvent       = Event(collab.EventReload)
	FileCollabSyncEvent         = Event(collab.EventSync)
	FileCollabParticipantsEvent = Event(collab.EventParticipants)
	FileCollabSavedEvent        = Event(collab.EventSaved)
	FileCollabConflictEvent     = Event(collab.EventConflict)
	FileCollabErrorEvent        = Event(collab.EventError)

	PermissionFileReadContent = collab.PermissionReadContent
	PermissionFileUpdate      = collab.PermissionUpdate
)
