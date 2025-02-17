from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
import models, database, schemas, utils, auth
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse

app = FastAPI()

models.Base.metadata.create_all(bind=database.engine)

# @app.post("/register", response_model=schemas.TokenData)
@app.post("/register")
def register(user_data: schemas.UserCreate, request: Request, db: Session = Depends(database.get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = utils.hash_password(user_data.password)
    
    # Create user entry
    new_user = models.User(email=user_data.email, hashed_password=hashed_password)
    db.add(new_user)

    # Create user details entry
    new_details = models.UserDetails(
        email=user_data.email,
        full_name=user_data.full_name,
        age=user_data.age,
        role=user_data.role
    )

    # device_info = request.headers.get("User-Agent", "Unknown device")
    
    # # Generate tokens
    # access_token = auth.create_access_token(user_data.email)
    # refresh_token = auth.create_refresh_token(db=db, user_id=user_data.email, device_info=device_info)

    response = JSONResponse(content = {"message": "User registered successfully, please login to continue"})
    response.status_code = 201

    # response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, max_age=3600, samesite="Lax", domain=None, path="/")
    # response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, max_age=604800, samesite="Lax", domain=None, path="/")

    # # committing DB changes once the cookie has been set
    db.add(new_details)
    db.commit()

    return response

@app.post("/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    access_token = request.cookies.get("access_token")

    if access_token: 
        if auth.verify_token(access_token, HTTPException(status_code=403, detail="Invalid access token")):
            return JSONResponse(
                content={"message": "User already logged in", "token_type": "bearer"},
                status_code=200
            )
        else:
            # In frontend, you can handle this trying to generate a new access token if refresh token is valid else redirect to login page
            raise HTTPException(status_code=403, detail="Invalid access token")

    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    
    if not user or not utils.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    device_info = request.headers.get("User-Agent", "Unknown device")
    
    access_token = auth.create_access_token(user.email)
    refresh_token = auth.create_refresh_token(db=db, user_id=form_data.username, device_info=device_info)

    response = JSONResponse(content = {"message": "User successfully logged in. Tokens are set", "token_type": "bearer"})
    response.status_code = 201

    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, max_age=3600, samesite="Lax", domain=None, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, max_age=604800, samesite="Lax", domain=None, path="/")

    db.commit()
    
    return response

@app.post("/refresh", response_model=schemas.TokenData)
def refresh_token(token: str, db: Session = Depends(database.get_db)):
    email = auth.verify_token(token, HTTPException(status_code=403, detail="Invalid refresh token"))
    
    new_access_token = auth.create_access_token(email)
    new_refresh_token = auth.create_refresh_token(email)
    
    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

@app.get("/protected")
def protected_route(current_user: models.User = Depends(auth.get_current_user)):
    return {"message": "You are authenticated!", "user": current_user.email}

@app.get("/user/me", response_model=schemas.UserDetailsResponse)
def get_user_details(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    user_details = db.query(models.UserDetails).filter(models.UserDetails.email == current_user.email).first()
    
    if not user_details:
        raise HTTPException(status_code=404, detail="User details not found")
    
    return user_details
