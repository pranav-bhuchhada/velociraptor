package api

import (
	"encoding/json"
	"io"
	"net/http"

	errors "github.com/go-errors/errors"

	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/api/authenticators"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	api_utils "www.velocidex.com/golang/velociraptor/api/utils"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const maxJITBodySize = 65536 // 64KB

func readJITBody(config_obj *config_proto.Config, w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJITBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		returnError(config_obj, w, 400, errors.New("Request body too large or unreadable"))
		return nil, false
	}
	return body, true
}

func jitRequestRoleHandler(config_obj *config_proto.Config) http.Handler {
	return api_utils.HandlerFunc(nil,
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				returnError(config_obj, w, 405, errors.New("Method not allowed"))
				return
			}

			org_id := authenticators.GetOrgIdFromRequest(r)
			org_id = utils.NormalizedOrgId(org_id)

			org_manager, err := services.GetOrgManager()
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			org_config_obj, err := org_manager.GetOrgConfig(org_id)
			if err != nil {
				returnError(config_obj, w, 404, err)
				return
			}

			user_record := GetUserInfo(r.Context(), org_config_obj)
			if user_record.Name == "" {
				returnError(config_obj, w, 403, errors.New("Unauthenticated"))
				return
			}

			body, ok := readJITBody(config_obj, w, r)
			if !ok {
				return
			}

			request := &api_proto.JITRequestRoleRequest{}
			if err := json.Unmarshal(body, request); err != nil {
				returnError(config_obj, w, 400, errors.New("Invalid request body"))
				return
			}

			if request.OrgId == "" {
				request.OrgId = org_id
			}

			jit_manager, err := services.GetJITManager(org_config_obj)
			if err != nil {
				returnError(config_obj, w, 500, errors.New("JIT service not available"))
				return
			}

			result, err := jit_manager.RequestRole(
				org_config_obj, user_record.Name, request)
			if err != nil {
				returnError(config_obj, w, 400, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		})
}

func jitApproveHandler(config_obj *config_proto.Config) http.Handler {
	return api_utils.HandlerFunc(nil,
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				returnError(config_obj, w, 405, errors.New("Method not allowed"))
				return
			}

			org_id := authenticators.GetOrgIdFromRequest(r)
			org_id = utils.NormalizedOrgId(org_id)

			org_manager, err := services.GetOrgManager()
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			org_config_obj, err := org_manager.GetOrgConfig(org_id)
			if err != nil {
				returnError(config_obj, w, 404, err)
				return
			}

			user_record := GetUserInfo(r.Context(), org_config_obj)
			if user_record.Name == "" {
				returnError(config_obj, w, 403, errors.New("Unauthenticated"))
				return
			}

			body, ok := readJITBody(config_obj, w, r)
			if !ok {
				return
			}

			approval := &api_proto.JITApprovalRequest{}
			if err := json.Unmarshal(body, approval); err != nil {
				returnError(config_obj, w, 400, errors.New("Invalid request body"))
				return
			}

			jit_manager, err := services.GetJITManager(org_config_obj)
			if err != nil {
				returnError(config_obj, w, 500, errors.New("JIT service not available"))
				return
			}

			result, err := jit_manager.ApproveOrDeny(
				org_config_obj, user_record.Name, approval)
			if err != nil {
				returnError(config_obj, w, 400, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		})
}

func jitRevokeHandler(config_obj *config_proto.Config) http.Handler {
	return api_utils.HandlerFunc(nil,
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				returnError(config_obj, w, 405, errors.New("Method not allowed"))
				return
			}

			org_id := authenticators.GetOrgIdFromRequest(r)
			org_id = utils.NormalizedOrgId(org_id)

			org_manager, err := services.GetOrgManager()
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			org_config_obj, err := org_manager.GetOrgConfig(org_id)
			if err != nil {
				returnError(config_obj, w, 404, err)
				return
			}

			user_record := GetUserInfo(r.Context(), org_config_obj)
			if user_record.Name == "" {
				returnError(config_obj, w, 403, errors.New("Unauthenticated"))
				return
			}

			body, ok := readJITBody(config_obj, w, r)
			if !ok {
				return
			}

			var req struct {
				RequestId string `json:"request_id"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				returnError(config_obj, w, 400, errors.New("Invalid request body"))
				return
			}

			jit_manager, err := services.GetJITManager(org_config_obj)
			if err != nil {
				returnError(config_obj, w, 500, errors.New("JIT service not available"))
				return
			}

			err = jit_manager.RevokeGrant(
				org_config_obj, user_record.Name, req.RequestId)
			if err != nil {
				returnError(config_obj, w, 400, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{}`))
		})
}

func jitListHandler(config_obj *config_proto.Config) http.Handler {
	return api_utils.HandlerFunc(nil,
		func(w http.ResponseWriter, r *http.Request) {
			org_id := authenticators.GetOrgIdFromRequest(r)
			org_id = utils.NormalizedOrgId(org_id)

			org_manager, err := services.GetOrgManager()
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			org_config_obj, err := org_manager.GetOrgConfig(org_id)
			if err != nil {
				returnError(config_obj, w, 404, err)
				return
			}

			user_record := GetUserInfo(r.Context(), org_config_obj)
			if user_record.Name == "" {
				returnError(config_obj, w, 403, errors.New("Unauthenticated"))
				return
			}

			jit_manager, err := services.GetJITManager(org_config_obj)
			if err != nil {
				returnError(config_obj, w, 500, errors.New("JIT service not available"))
				return
			}

			// Only permanent admins can see all requests
			is_admin, _ := services.CheckPermanentAccess(
				org_config_obj, user_record.Name, acls.SERVER_ADMIN)

			status_str := r.URL.Query().Get("status")
			username := r.URL.Query().Get("username")

			if !is_admin {
				// Force non-admins to only see their own requests
				username = user_record.Name
			}

			var status api_proto.JITRequestStatus = -1
			switch status_str {
			case "PENDING":
				status = api_proto.JIT_STATUS_PENDING
			case "APPROVED":
				status = api_proto.JIT_STATUS_APPROVED
			case "DENIED":
				status = api_proto.JIT_STATUS_DENIED
			case "EXPIRED":
				status = api_proto.JIT_STATUS_EXPIRED
			case "REVOKED":
				status = api_proto.JIT_STATUS_REVOKED
			}

			result, err := jit_manager.ListRequests(
				org_config_obj, status, username)
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		})
}

func jitMyGrantsHandler(config_obj *config_proto.Config) http.Handler {
	return api_utils.HandlerFunc(nil,
		func(w http.ResponseWriter, r *http.Request) {
			org_id := authenticators.GetOrgIdFromRequest(r)
			org_id = utils.NormalizedOrgId(org_id)

			org_manager, err := services.GetOrgManager()
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			org_config_obj, err := org_manager.GetOrgConfig(org_id)
			if err != nil {
				returnError(config_obj, w, 404, err)
				return
			}

			user_record := GetUserInfo(r.Context(), org_config_obj)
			if user_record.Name == "" {
				returnError(config_obj, w, 403, errors.New("Unauthenticated"))
				return
			}

			jit_manager, err := services.GetJITManager(org_config_obj)
			if err != nil {
				returnError(config_obj, w, 500, errors.New("JIT service not available"))
				return
			}

			grants, err := jit_manager.GetActiveGrants(
				org_config_obj, user_record.Name)
			if err != nil {
				returnError(config_obj, w, 500, err)
				return
			}

			result := &api_proto.JITRoleRequests{Items: grants}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		})
}
