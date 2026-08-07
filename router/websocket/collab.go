package websocket

import (
	"emperror.dev/errors"

	"github.com/mythicalltd/featherwings/internal/models"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/collab"
)

const ErrMissingPermissionMessage = "missing permission"

func (h *Handler) handleCollab(m Message) error {
	if len(m.Args) < 1 {
		return nil
	}
	path := m.Args[0]
	jwt := h.GetJwt()
	if jwt == nil {
		return ErrJwtNotPresent
	}

	userUUID := jwt.UserUUID
	userName := userUUID
	manager := h.server.Collab()

	needUpdate := m.Event == FileCollabUpdateEvent || m.Event == FileCollabSaveEvent || m.Event == FileCollabReloadEvent
	perm := PermissionFileReadContent
	if needUpdate {
		perm = PermissionFileUpdate
	}
	if !jwt.HasPermission(perm) {
		_ = h.SendJson(Message{
			Event: FileCollabErrorEvent,
			Args:  []string{path, ErrMissingPermissionMessage},
		})
		return nil
	}

	var err error
	switch m.Event {
	case FileCollabSubscribeEvent:
		editor := ""
		if len(m.Args) > 1 {
			editor = m.Args[1]
		}
		err = manager.Subscribe(h.Uuid(), userUUID, userName, nil, path, editor)
	case FileCollabUnsubscribeEvent:
		editor := ""
		if len(m.Args) > 1 {
			editor = m.Args[1]
		}
		err = manager.Unsubscribe(h.Uuid(), path, editor)
	case FileCollabUpdateEvent:
		if len(m.Args) < 3 {
			return nil
		}
		finished := m.Args[1] == "1"
		chunk := m.Args[2]
		editor := ""
		if len(m.Args) > 3 {
			editor = m.Args[3]
		}
		err = manager.ApplyUpdate(h.Uuid(), path, finished, chunk, editor)
	case FileCollabAwarenessEvent:
		if len(m.Args) < 2 {
			return nil
		}
		err = manager.RelayAwareness(h.Uuid(), path, m.Args[1])
	case FileCollabSaveEvent:
		force := len(m.Args) > 1 && m.Args[1] == "1"
		expected := ""
		if len(m.Args) > 2 {
			expected = m.Args[2]
		}
		err = manager.Save(h.Uuid(), userUUID, path, force, expected)
		if err == nil {
			h.server.SaveActivity(h.ra, server.ActivitySftpWrite, models.ActivityMeta{
				"file": path,
			})
		}
	case FileCollabReloadEvent:
		err = manager.Reload(h.Uuid(), path)
	default:
		return nil
	}

	if err == nil {
		return nil
	}
	if collab.UserError(err) {
		_ = h.SendJson(Message{
			Event: FileCollabErrorEvent,
			Args:  []string{path, err.Error()},
		})
		return nil
	}
	return errors.WithMessage(err, "collab")
}
