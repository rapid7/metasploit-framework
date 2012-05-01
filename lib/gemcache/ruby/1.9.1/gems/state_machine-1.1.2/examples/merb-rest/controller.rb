class Users < Application
  # GET /users
  def index
    @users = User.all
    display @users
  end
  
  # GET /users/1
  def show(id)
    @user = User.get(id)
    raise NotFound unless @user
    display @user
  end
  
  # GET /users/new
  def new
    only_provides :html
    @user = User.new
    display @user
  end
  
  # GET /users/1/edit
  def edit(id)
    only_provides :html
    @user = User.get(id)
    raise NotFound unless @user
    display @user
  end
  
  # POST /users
  def create(user)
    @user = User.new(user)
    if @user.save
      redirect resource(@user), :message => {:notice => "User was successfully created"}
    else
      message[:error] = "User failed to be created"
      render :new
    end
  end
  
  # PUT /users/1
  def update(id, user)
    @user = User.get(id)
    raise NotFound unless @user
    if @user.update_attributes(user)
       redirect resource(@user)
    else
      display @user, :edit
    end
  end
end
