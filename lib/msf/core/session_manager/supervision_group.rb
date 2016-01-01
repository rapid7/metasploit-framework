class Msf::SessionManager::SupervisionGroup < Celluloid::SupervisionGroup
  pool Msf::SessionManager::Initializer, as: :msf_session_manager_initializer_pool
  supervise Msf::SessionManager::ID, as: :msf_session_manager_id
end